//! Block chains: an admitted translation is entered without its block hook
//! while its page guard is open and the budget covers its weight. Every
//! other entry calls the hook, and the guest result never depends on it.
use crate::{Core, test_support};
use fujimod_emulator_cpu::{Block, BlockChain, Cpu, Hook, HookRange, Model, Register, Run, arm};
use std::ffi::c_void;
use std::ptr::NonNull;

const ROUNDS: u32 = 40;
/// The admitted block: two instructions at 0x1100.
const INNER: u64 = 0x1100;
const KEY: u32 = 7;
const TAG: u64 = 0x1234_5678_9abc_def0;

struct Observer {
    cpu: *const Core,
    record: Option<NonNull<BlockChain>>,
    /// Hook calls per block: the loop head, the inner block, the loop tail.
    calls: [u32; 3],
    /// Admit the inner block from its own hook, with this weight.
    admit: Option<u32>,
    /// Set the budget to this in the inner block's hook.
    grant: Option<i64>,
    /// Ask for a stop in this call of the loop head's hook.
    stop_at: Option<u32>,
    /// Withdraw the admission in this call of the inner block's hook, and
    /// renew the budget.
    withdraw_at: Option<u32>,
    admitted: Result<(), String>,
}

unsafe fn entered(block: Block, data: *mut c_void) {
    let seen = unsafe { &mut *data.cast::<Observer>() };
    let cpu = unsafe { &*seen.cpu };
    match block.address {
        0x1004 => {
            seen.calls[0] += 1;
            if seen.stop_at == Some(seen.calls[0]) {
                cpu.stop().unwrap();
            }
        }
        INNER => {
            seen.calls[1] += 1;
            if seen.withdraw_at == Some(seen.calls[1]) {
                seen.admit = None;
                seen.grant = Some(1000);
                seen.admitted = cpu.admit_block(0, KEY, TAG);
            }
            if let Some(weight) = seen.admit {
                seen.admitted = cpu.admit_block(weight, KEY, TAG);
            }
            if let (Some(grant), Some(record)) = (seen.grant.take(), seen.record) {
                unsafe { (*record.as_ptr()).budget = grant };
            }
        }
        0x1200 => seen.calls[2] += 1,
        _ => {}
    }
}

fn words(cpu: &Core, address: u64, words: &[u32]) {
    let bytes = words
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect::<Vec<_>>();
    cpu.write_memory(address, &bytes).unwrap();
}

fn branch(from: u64, to: u64) -> u32 {
    0xea00_0000 | (((to as i64 - from as i64 - 8) >> 2) as u32 & 0x00ff_ffff)
}

/// r0 counts rounds, r1 counts entries of the inner block; both start at 0.
/// Three blocks per round; the run ends at 0x1208 after `ROUNDS` rounds.
fn machine(chains: bool) -> (Box<Core>, Box<Observer>) {
    let cpu = Box::new(
        test_support::library()
            .open(Model::CortexA7, 1 << 20)
            .unwrap(),
    );
    cpu.map_zeroed(0, 0x8000, 7).unwrap();
    cpu.write_register(arm::CPSR, &0xd3u32.to_le_bytes()).unwrap();
    // 0x1004 is the loop head: add r0, r0, #1; b INNER
    words(&cpu, 0x1004, &[0xe280_0001, branch(0x1008, INNER)]);
    // INNER: add r1, r1, #1; b 0x1200
    words(&cpu, INNER, &[0xe281_1001, branch(INNER + 4, 0x1200)]);
    // 0x1200: cmp r0, #ROUNDS; bne 0x1004; 0x1208: b .
    words(
        &cpu,
        0x1200,
        &[0xe350_0000 | ROUNDS, 0x1a00_0000 | (branch(0x1204, 0x1004) & 0x00ff_ffff), 0xeaff_fffe],
    );
    let record = if chains {
        Some(cpu.block_chains(true).unwrap().expect("the pinned engine has block chains"))
    } else {
        None
    };
    let mut seen = Box::new(Observer {
        cpu: &*cpu,
        record,
        calls: [0; 3],
        admit: None,
        grant: None,
        stop_at: None,
        withdraw_at: None,
        admitted: Ok(()),
    });
    unsafe {
        cpu.install_hook(Hook::Block {
            callback: entered,
            data: (&mut *seen as *mut Observer).cast(),
            range: HookRange::All,
        })
    }
    .unwrap();
    (cpu, seen)
}

fn run(cpu: &Core, begin: u64) {
    cpu.run(Run {
        begin,
        until: Some(0x1208),
        instructions: None,
        watchdog_us: 0,
    })
    .unwrap();
}

fn register(cpu: &Core, register: Register) -> u32 {
    let mut out = [0; 4];
    cpu.read_register(register, &mut out).unwrap();
    u32::from_le_bytes(out)
}

fn guest(cpu: &Core) -> (u32, u32, u32) {
    (register(cpu, arm::CORE[0]), register(cpu, arm::CORE[1]), register(cpu, Register::Pc))
}

fn open_guard(record: NonNull<BlockChain>, key: u32) {
    unsafe { (*record.as_ptr()).guards[BlockChain::slot(INNER)] = key };
}

fn budget(record: NonNull<BlockChain>) -> (i64, u64) {
    unsafe { ((*record.as_ptr()).budget, (*record.as_ptr()).last) }
}

#[test]
fn every_block_calls_its_hook_without_chains() {
    let (cpu, seen) = machine(false);
    run(&cpu, 0x1004);
    assert_eq!(seen.calls, [ROUNDS; 3]);
    assert_eq!(guest(&cpu), (ROUNDS, ROUNDS, 0x1208));
}

#[test]
fn enabled_chains_change_nothing_until_a_block_is_admitted_and_granted() {
    // Nothing admitted: a budget alone enters no block without its hook.
    let (cpu, mut seen) = machine(true);
    let record = seen.record.unwrap();
    open_guard(record, KEY);
    seen.grant = Some(1000);
    run(&cpu, 0x1004);
    assert_eq!(seen.calls, [ROUNDS; 3]);
    assert_eq!(budget(record).0, 1000);
    assert_eq!(guest(&cpu), (ROUNDS, ROUNDS, 0x1208));

    // Admitted, guard open, no budget.
    let (cpu, mut seen) = machine(true);
    open_guard(seen.record.unwrap(), KEY);
    seen.admit = Some(2);
    run(&cpu, 0x1004);
    assert_eq!(seen.calls, [ROUNDS; 3]);
    assert_eq!(seen.admitted, Ok(()));

    // Admitted and granted, but the guard holds another page's key, or none.
    for key in [0, KEY + 1] {
        let (cpu, mut seen) = machine(true);
        let record = seen.record.unwrap();
        open_guard(record, key);
        seen.admit = Some(2);
        seen.grant = Some(1000);
        run(&cpu, 0x1004);
        assert_eq!(seen.calls, [ROUNDS; 3]);
        assert_eq!(budget(record).0, 1000);
    }
}

#[test]
fn an_admitted_block_spends_the_budget_instead_of_calling_its_hook() {
    let (cpu, mut seen) = machine(true);
    let record = seen.record.unwrap();
    open_guard(record, KEY);
    seen.admit = Some(2);
    // Five entries' worth, and one unit that buys nothing.
    seen.grant = Some(11);
    run(&cpu, 0x1004);
    // The first entry admits and grants; the next five pass the hook; the
    // budget then no longer covers the weight and every entry calls it.
    assert_eq!(seen.calls, [ROUNDS, ROUNDS - 5, ROUNDS]);
    assert_eq!(budget(record), (1, TAG));
    // The guest ran the same instructions.
    assert_eq!(guest(&cpu), (ROUNDS, ROUNDS, 0x1208));
}

#[test]
fn a_requested_stop_is_served_before_a_chained_entry() {
    let (cpu, mut seen) = machine(true);
    let record = seen.record.unwrap();
    open_guard(record, KEY);
    seen.admit = Some(2);
    seen.grant = Some(1000);
    // The loop head's hook asks for a stop in round 10. The head's own exit
    // test serves it before the head runs; the admitted block is not entered.
    seen.stop_at = Some(10);
    run(&cpu, 0x1004);
    assert_eq!(guest(&cpu), (9, 9, 0x1004));
    // Entries 2..=9 of the inner block were chained.
    assert_eq!(seen.calls, [10, 1, 9]);
    assert_eq!(budget(record), (1000 - 8 * 2, TAG));
    // Resumed, the run ends as without chains.
    seen.stop_at = None;
    run(&cpu, 0x1004);
    assert_eq!(guest(&cpu), (ROUNDS, ROUNDS, 0x1208));
    // The stopped entry of the head calls its hook again.
    assert_eq!(seen.calls, [ROUNDS + 1, 1, ROUNDS]);
    assert_eq!(budget(record).0, 1000 - (i64::from(ROUNDS) - 1) * 2);
}

#[test]
fn an_admission_ends_with_its_translation() {
    let (cpu, mut seen) = machine(true);
    let record = seen.record.unwrap();
    open_guard(record, KEY);
    seen.admit = Some(2);
    seen.grant = Some(1000);
    seen.stop_at = Some(10);
    run(&cpu, 0x1004);
    assert_eq!(seen.calls[1], 1);
    // Discarded translations take their admissions along: the new
    // translation of the same code calls its hook until it is admitted.
    cpu.invalidate_code(None).unwrap();
    unsafe { (*record.as_ptr()).budget = 1000 };
    seen.admit = None;
    seen.stop_at = None;
    run(&cpu, 0x1004);
    assert_eq!(seen.calls[1], 1 + ROUNDS - 9);
    assert_eq!(budget(record).0, 1000);
    assert_eq!(guest(&cpu), (ROUNDS, ROUNDS, 0x1208));
}

#[test]
fn a_withdrawn_admission_calls_the_hook_again() {
    let (cpu, mut seen) = machine(true);
    let record = seen.record.unwrap();
    open_guard(record, KEY);
    seen.admit = Some(2);
    // Enough for four chained entries. The sixth entry calls the hook, which
    // withdraws the admission and renews the budget.
    seen.grant = Some(8);
    seen.withdraw_at = Some(2);
    run(&cpu, 0x1004);
    assert_eq!(seen.admitted, Ok(()));
    assert_eq!(seen.calls, [ROUNDS, ROUNDS - 4, ROUNDS]);
    assert_eq!(budget(record).0, 1000);
    assert_eq!(guest(&cpu), (ROUNDS, ROUNDS, 0x1208));
}

#[test]
fn a_block_is_admitted_only_from_its_own_hook() {
    let (cpu, _seen) = machine(true);
    assert!(cpu.admit_block(2, KEY, TAG).is_err());
    run(&cpu, 0x1004);
    assert!(cpu.admit_block(2, KEY, TAG).is_err());
}
