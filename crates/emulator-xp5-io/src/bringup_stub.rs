//! Scripted register stubs for bring-up runs of the stock first-stage setup.
//!
//! The stock XP5 setup polls a few blocks that the catalog does not model yet
//! (DDR PHY mailbox, a memory-configuration status pair, ...). A stub window
//! answers each listed register with one of a few fixed behaviours so the
//! setup can proceed in the emulator. Every unlisted register in the window
//! stores its last write and reads it back. This is a bring-up aid, not a
//! model: the real hardware's behaviour behind these registers is unknown.
use fujimod_emulator_devices::{Cx, Device};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Reads always return `value`.
    Constant,
    /// Reads alternate between 0 and `value`, starting with 0.
    Toggle,
    /// Writes are stored; reads return 0 (a self-clearing command register).
    Command,
    /// Reads return `value` once a write has happened, 0 before.
    AfterWrite,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Register {
    pub offset: u64,
    pub mode: Mode,
    #[serde(default)]
    pub value: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Options {
    pub registers: Vec<Register>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct State {
    base: u64,
    size: u64,
    registers: Vec<Register>,
    stored: BTreeMap<u64, u64>,
    phase: BTreeMap<u64, bool>,
    written: BTreeMap<u64, bool>,
}

pub struct BringupStub {
    state: State,
}

impl BringupStub {
    pub fn new(base: u64, size: u64, options: Options) -> Result<Self, String> {
        if size == 0 || base.checked_add(size).is_none() {
            return Err("invalid bring-up stub window".into());
        }
        if options.registers.iter().any(|r| r.offset >= size) {
            return Err("bring-up stub register outside its window".into());
        }
        Ok(Self {
            state: State {
                base,
                size,
                registers: options.registers,
                stored: BTreeMap::new(),
                phase: BTreeMap::new(),
                written: BTreeMap::new(),
            },
        })
    }

    fn mask(size: u8) -> u64 {
        match size {
            1 => 0xff,
            2 => 0xffff,
            4 => 0xffff_ffff,
            _ => u64::MAX,
        }
    }
}

impl Device for BringupStub {
    fn name(&self) -> &'static str {
        "bringup-stub"
    }

    fn read(&mut self, cx: &mut Cx<'_>, address: u64, size: u8) -> u64 {
        let Some(offset) = address.checked_sub(self.state.base).filter(|o| *o < self.state.size) else {
            cx.unmodeled();
            return 0;
        };
        let mask = Self::mask(size);
        if let Some(register) = self.state.registers.iter().find(|r| r.offset == offset) {
            let value = match register.mode {
                Mode::Constant => register.value,
                Mode::Toggle => {
                    let high = self.state.phase.entry(offset).or_insert(false);
                    let value = if *high { register.value } else { 0 };
                    *high = !*high;
                    value
                }
                Mode::Command => 0,
                Mode::AfterWrite => {
                    if self.state.written.get(&offset).copied().unwrap_or(false) {
                        register.value
                    } else {
                        0
                    }
                }
            };
            return value & mask;
        }
        self.state.stored.get(&offset).copied().unwrap_or(0) & mask
    }

    fn write(&mut self, cx: &mut Cx<'_>, address: u64, size: u8, value: u64) {
        let Some(offset) = address.checked_sub(self.state.base).filter(|o| *o < self.state.size) else {
            cx.unmodeled();
            return;
        };
        self.state.written.insert(offset, true);
        self.state.stored.insert(offset, value & Self::mask(size));
    }

    fn save(&self) -> Value {
        serde_json::to_value(&self.state).unwrap()
    }

    fn restore(&mut self, value: &Value) -> Result<(), String> {
        self.state = serde_json::from_value(value.clone()).map_err(|error| error.to_string())?;
        Ok(())
    }
}
