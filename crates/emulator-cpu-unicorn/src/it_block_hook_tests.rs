//! A memory hook that returns into its translated block leaves ITSTATE as
//! translated code expects it. The hook is given the state of the accessing
//! instruction, ITSTATE included; if that stayed behind, a block that goes on
//! past the IT block would end with it set, and the first instruction of the
//! next block would become conditional.
use crate::{Core, test_support};
use fujimod_emulator_cpu::{Access, Cpu, Hook, HookRange, Model, Register, Run, arm};
use std::ffi::c_void;

unsafe fn accessed(_: Access, _: u64, _: i32, _: i64, data: *mut c_void) {
    unsafe { *data.cast::<u32>() += 1 };
}

/// `access` is the conditional instruction inside the IT block: a store or a
/// load through R2. After it the block changes the flags and branches; the
/// branch target adds 5 to R3.
fn run(access: u16, hook: Option<(bool, bool)>) -> (u32, u32, u32) {
    let cpu: Core = test_support::library().open(Model::CortexA7, 1 << 20).unwrap();
    cpu.map_zeroed(0, 0x8000, 7).unwrap();
    cpu.write_register(arm::CPSR, &0xf3u32.to_le_bytes()).unwrap();
    let mut calls = Box::new(0u32);
    if let Some((read, write)) = hook {
        unsafe {
            cpu.install_hook(Hook::Memory {
                callback: accessed,
                data: (&mut *calls as *mut u32).cast(),
                read,
                write,
                range: HookRange::Inclusive { begin: 0x4000, end: 0x4fff },
            })
        }
        .unwrap();
    }
    // movs r3,#0; cmp r0,r0; it eq; <access>; movs r4,#1; b .+2;
    // adds r3,#5; b .
    let code = [0x2300, 0x4280, 0xbf08, access, 0x2401, 0xe7ff, 0x3305, 0xe7fe];
    let bytes = code.iter().flat_map(|w: &u16| w.to_le_bytes()).collect::<Vec<_>>();
    cpu.write_memory(0x1000, &bytes).unwrap();
    cpu.write_register(arm::CORE[2], &0x4000u32.to_le_bytes()).unwrap();
    cpu.run(Run { begin: 0x1001, until: Some(0x100e), instructions: None, watchdog_us: 0 })
        .unwrap();
    let read = |register| {
        let mut out = [0; 4];
        cpu.read_register(register, &mut out).unwrap();
        u32::from_le_bytes(out)
    };
    (read(arm::CORE[3]), read(Register::Pc), *calls)
}

#[test]
fn a_hooked_store_in_an_it_block_leaves_no_itstate_behind() {
    // streq r1,[r2]
    assert_eq!(run(0x6011, None), (5, 0x100e, 0));
    assert_eq!(run(0x6011, Some((false, true))), (5, 0x100e, 1));
}

#[test]
fn a_hooked_load_in_an_it_block_leaves_no_itstate_behind() {
    // ldreq r1,[r2]
    assert_eq!(run(0x6811, None), (5, 0x100e, 0));
    assert_eq!(run(0x6811, Some((true, false))), (5, 0x100e, 1));
}
