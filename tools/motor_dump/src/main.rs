/*!
Motor Dump – Diagnostic Register Snapshot Tool

Author: Daniel Ritchie

Purpose
-------
This tool performs a forensic-style snapshot of motor EEPROM and RAM
registers over a serial bus. It is designed for diagnostics, debugging,
and post-mortem analysis rather than human-friendly presentation.

Key properties:
- Table-driven register map (single source of truth)
- Raw bytes are always preserved
- Read success/failure is explicitly recorded
- Transport-layer errors are captured, not hidden
- Known bitfields are decoded, unknown bits are retained
- Output is schema-versioned JSON suitable for diffing and archival

What this tool is *not*:
- It does not attempt to "fix" motor state
- It does not retry reads unless explicitly implemented
- It does not assume registers are readable or valid
- It does not optimize for readability over accuracy

Typical use cases:
- Diagnosing hardware faults (e.g. voltage, thermal, overload)
- Comparing motor state before/after configuration changes
- Investigating intermittent bus or register read failures
- Capturing ground-truth data to share with firmware or hardware teams

Usage
-----
cargo run -- <PORT> <LABEL> <MOTOR_ID>...

Example:
cargo run -- COM7 overvoltage_test 10 11 12 13

The resulting JSON file is intended to be treated as raw diagnostic
evidence and should not be edited or normalized after capture.

Notes
-----
This tool assumes a best-effort read model: a motor may be reachable
while individual register reads fail. Such failures are recorded
explicitly and are considered diagnostically meaningful.
*/

use anyhow::Result;
use clap::Parser;
use chrono::Utc;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;

use reachy_mini_motor_controller::ReachyMiniMotorController;

/* =========================
   CLI
   ========================= */

#[derive(Parser)]
struct Args {
    /// Serial port (COM7, /dev/ttyUSB0)
    port: String,

    /// Label (bad_state_7v_windows, good_state_5v, etc)
    label: String,

    /// Motor IDs
    motor_ids: Vec<u8>,
}

/* =========================
   Dump structures
   ========================= */

#[derive(Serialize)]
struct Dump {
    schema_version: u8,
    timestamp_utc: String,
    port: String,
    label: String,
    motors: BTreeMap<u8, MotorDump>,
}

#[derive(Serialize)]
struct MotorDump {
    reachable: bool,
    eeprom: BTreeMap<&'static str, RegisterDump>,
    ram: BTreeMap<&'static str, RegisterDump>,
}

#[derive(Serialize)]
struct RegisterDump {
    raw: Vec<u8>,
    decoded: Option<Value>,
    unit: Option<&'static str>,
    read_ok: bool,
    error: Option<String>,
}

/* =========================
   Register definitions
   ========================= */

#[derive(Clone, Copy)]
enum RegisterKind {
    Eeprom,
    Ram,
}

#[derive(Clone, Copy)]
struct RegisterDef {
    name: &'static str,
    addr: u8,
    len: u8,
    kind: RegisterKind,
    unit: Option<&'static str>,
    decoder: Option<fn(&[u8]) -> Value>,
}

/* =========================
   Primitive decoders
   ========================= */

fn dec_u8(v: &[u8]) -> Value {
    v.get(0).copied().into()
}

fn dec_u16_le(v: &[u8]) -> Value {
    if v.len() == 2 {
        u16::from_le_bytes([v[0], v[1]]).into()
    } else {
        Value::Null
    }
}

fn dec_i16_le(v: &[u8]) -> Value {
    if v.len() == 2 {
        i16::from_le_bytes([v[0], v[1]]).into()
    } else {
        Value::Null
    }
}

fn dec_voltage_01v(v: &[u8]) -> Value {
    if v.len() == 2 {
        let raw = u16::from_le_bytes([v[0], v[1]]);
        (raw as f64 * 0.1).into()
    } else {
        Value::Null
    }
}

/* =========================
   Bitfield decoders (exhaustive)
   ========================= */

fn dec_hw_error(v: &[u8]) -> Value {
    let raw = match v.first() {
        Some(b) => *b,
        None => return Value::Null,
    };

    let known_map = [
        (0, "input_voltage"),
        (1, "overheating"),
        (2, "encoder"),
        (3, "electrical_shock"),
        (4, "overload"),
    ];

    let mut known: Vec<Value> = Vec::new();
    let mut unknown_bits: Vec<Value> = Vec::new();

    for bit in 0..8 {
        if raw & (1 << bit) != 0 {
            if let Some((_, name)) = known_map.iter().find(|(b, _)| *b == bit) {
                known.push(Value::from(*name));
            } else {
                unknown_bits.push(Value::from(bit));
            }
        }
    }

    serde_json::json!({
        "raw": raw,
        "known": known,
        "unknown_bits": unknown_bits,
    })
}

fn dec_shutdown(v: &[u8]) -> Value {
    let raw = match v.first() {
        Some(b) => *b,
        None => return Value::Null,
    };

    let known_map = [
        (0, "overheating"),
        (1, "encoder"),
        (2, "electrical_shock"),
        (3, "overload"),
        (4, "input_voltage"),
    ];

    let mut enabled: Vec<Value> = Vec::new();
    let mut unknown_bits: Vec<Value> = Vec::new();

    for bit in 0..8 {
        if raw & (1 << bit) != 0 {
            if let Some((_, name)) = known_map.iter().find(|(b, _)| *b == bit) {
                enabled.push(Value::from(*name));
            } else {
                unknown_bits.push(Value::from(bit));
            }
        }
    }

    serde_json::json!({
        "raw": raw,
        "enabled": enabled,
        "unknown_bits": unknown_bits,
    })
}

/* =========================
   Register table (single source of truth)
   ========================= */

static REGISTERS: &[RegisterDef] = &[
    // EEPROM
    RegisterDef { name: "id", addr: 7, len: 1, kind: RegisterKind::Eeprom, unit: None, decoder: Some(dec_u8) },
    RegisterDef { name: "baud_rate", addr: 8, len: 1, kind: RegisterKind::Eeprom, unit: None, decoder: Some(dec_u8) },
    RegisterDef { name: "return_delay", addr: 9, len: 1, kind: RegisterKind::Eeprom, unit: Some("µs"), decoder: Some(dec_u8) },
    RegisterDef { name: "operating_mode", addr: 11, len: 1, kind: RegisterKind::Eeprom, unit: None, decoder: Some(dec_u8) },
    RegisterDef { name: "homing_offset", addr: 20, len: 4, kind: RegisterKind::Eeprom, unit: Some("ticks"), decoder: None },
    RegisterDef { name: "temperature_limit", addr: 31, len: 1, kind: RegisterKind::Eeprom, unit: Some("°C"), decoder: Some(dec_u8) },
    RegisterDef { name: "voltage_limit_high", addr: 32, len: 2, kind: RegisterKind::Eeprom, unit: Some("V"), decoder: Some(dec_voltage_01v) },
    RegisterDef { name: "voltage_limit_low", addr: 34, len: 2, kind: RegisterKind::Eeprom, unit: Some("V"), decoder: Some(dec_voltage_01v) },
    RegisterDef { name: "current_limit", addr: 38, len: 2, kind: RegisterKind::Eeprom, unit: Some("mA"), decoder: Some(dec_u16_le) },
    RegisterDef { name: "max_position_limit", addr: 48, len: 4, kind: RegisterKind::Eeprom, unit: Some("ticks"), decoder: None },
    RegisterDef { name: "min_position_limit", addr: 52, len: 4, kind: RegisterKind::Eeprom, unit: Some("ticks"), decoder: None },
    RegisterDef { name: "shutdown", addr: 63, len: 1, kind: RegisterKind::Eeprom, unit: None, decoder: Some(dec_shutdown) },

    // RAM
    RegisterDef { name: "torque_enable", addr: 64, len: 1, kind: RegisterKind::Ram, unit: None, decoder: Some(dec_u8) },
    RegisterDef { name: "hardware_error_status", addr: 70, len: 1, kind: RegisterKind::Ram, unit: None, decoder: Some(dec_hw_error) },
    RegisterDef { name: "present_current", addr: 126, len: 2, kind: RegisterKind::Ram, unit: Some("mA"), decoder: Some(dec_i16_le) },
    RegisterDef { name: "present_input_voltage", addr: 144, len: 2, kind: RegisterKind::Ram, unit: Some("V"), decoder: Some(dec_voltage_01v) },
    RegisterDef { name: "present_temperature", addr: 146, len: 1, kind: RegisterKind::Ram, unit: Some("°C"), decoder: Some(dec_u8) },
];

/* =========================
   Main
   ========================= */

fn main() -> Result<()> {
    let args = Args::parse();

    let mut ctrl = ReachyMiniMotorController::new(&args.port)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    let mut motors = BTreeMap::new();

    for id in args.motor_ids {
        eprintln!("Dumping motor {id}…");
        motors.insert(id, dump_motor(&mut ctrl, id));
    }

    let dump = Dump {
        schema_version: 1,
        timestamp_utc: Utc::now().to_rfc3339(),
        port: args.port,
        label: args.label.clone(),
        motors,
    };

    let filename = format!("motor_dump_{}.json", args.label);
    let mut file = File::create(&filename)?;
    file.write_all(serde_json::to_string_pretty(&dump)?.as_bytes())?;

    println!("✅ wrote {filename}");
    Ok(())
}

/* =========================
   Core table-driven dumper
   ========================= */

fn dump_motor(ctrl: &mut ReachyMiniMotorController, id: u8) -> MotorDump {
    let reachable = ctrl.read_raw_bytes(id, 7, 1).is_ok();

    if !reachable {
        return MotorDump {
            reachable: false,
            eeprom: BTreeMap::new(),
            ram: BTreeMap::new(),
        };
    }

    let mut eeprom = BTreeMap::new();
    let mut ram = BTreeMap::new();

    for reg in REGISTERS {
        let read = ctrl.read_raw_bytes(id, reg.addr, reg.len);

        let (raw, read_ok, error) = match read {
            Ok(v) => (v, true, None),
            Err(e) => (Vec::new(), false, Some(e.to_string())),
        };

        let decoded = if read_ok {
            reg.decoder.map(|f| f(&raw))
        } else {
            None
        };

        let entry = RegisterDump {
            raw,
            decoded,
            unit: reg.unit,
            read_ok,
            error,
        };

        match reg.kind {
            RegisterKind::Eeprom => {
                eeprom.insert(reg.name, entry);
            }
            RegisterKind::Ram => {
                ram.insert(reg.name, entry);
            }
        }
    }

    MotorDump {
        reachable: true,
        eeprom,
        ram,
    }
}
