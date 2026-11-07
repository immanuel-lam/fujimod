//! Local bring-up harness for the X-T5 4.31 firmware on FujiMod's XP5 board.
//!
//! This is not upstream FujiMod code. It assembles the catalog's XP5 SoC
//! description with the X-T5 body and runs the stock update's first-stage
//! loader, standing in for the boot ROM (which we do not have): it copies the
//! loader from flash into boot SRAM and starts core 0 at its entry.

use fujimod_catalog_resolution::ResolvedConfiguration;
use fujimod_emulator::board::{bus::Mode, factory};
use fujimod_emulator_boot::graph::{ProcessorStart, assemble_with_starts};
use fujimod_emulator_cpu::{Register, arm64};
use fujimod_emulator_xp5_board::{board as xp5_board, boot};
use fujimod_emulator_xp5_display::display;
use fujimod_emulator_xp5_storage::flash_storage;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Instant,
};

const CONFIGURATION: &str = "xt5-431";
const PROFILE: &str = "xt5-431";
const BOOT_SRAM: u64 = 0xff80_0000;
// Body bus-drain note: the DRAM map ends at 0x60000000 (the catalog run limit 1 GiB is only the
// kernel's first identity map); DMA targets 0x40010000.
// After first-start setup the firmware writes at 0x7EC00000, so the body has at least
// 2 GiB; the body's bus-drain read at 0x60000000 then lands in DRAM.
const DRAM_LIMIT: u64 = 0x8000_0000;
const HANDOFF_PC: u64 = 0x5847c;

struct Args {
    update: PathBuf,
    instructions: u64,
    chunk: u64,
    quantum: usize,
    engine: factory::Engine,
    mode: Mode,
    start: String,
    images: Vec<(u64, PathBuf)>,
    stop_at: Vec<u64>,
    state_out: Option<PathBuf>,
    quiet: bool,
    omit: Vec<String>,
    secondaries: bool,
    trace: Option<PathBuf>,
    trace_limit: usize,
    trace_after_ms: u64,
    watch_ranges: Vec<(u64, u64)>,
    set_regs: Vec<(Option<usize>, String, u64)>,
    watch: Vec<u64>,
    pokes: Vec<(u64, u32)>,
    frames_dir: Option<PathBuf>,
    policy: Option<String>,
    dumps: Vec<(u64, usize)>,
    presses: Vec<(u64, String, u64)>,
    all_frames: bool,
    allow_modified: bool,
    save_snapshot: Option<PathBuf>,
    load_snapshot: Option<PathBuf>,
    dump_files: Vec<(u64, usize, PathBuf)>,
}

fn parse_u64(text: &str) -> Result<u64, String> {
    let text = text.replace('_', "");
    if let Some(hex) = text.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).map_err(|e| format!("{text}: {e}"))
    } else {
        text.parse().map_err(|e| format!("{text}: {e}"))
    }
}

fn args() -> Result<Args, String> {
    let mut out = Args {
        update: PathBuf::from("FWUP0030.DAT"),
        instructions: 50_000_000,
        chunk: 1_000_000,
        quantum: 1000,
        engine: factory::Engine::Unicorn,
        mode: Mode::Discovery,
        start: "stage0".into(),
        images: vec![],
        stop_at: vec![HANDOFF_PC],
        state_out: None,
        quiet: false,
        omit: vec!["statistics".into(), "panel-spi".into()],
        secondaries: false,
        trace: None,
        trace_limit: 200_000,
        trace_after_ms: 0,
        watch_ranges: vec![],
        set_regs: vec![],
        watch: vec![],
        pokes: vec![],
        frames_dir: None,
        policy: None,
        dumps: vec![],
        presses: vec![],
        all_frames: false,
        allow_modified: false,
        save_snapshot: None,
        load_snapshot: None,
        dump_files: vec![],
    };
    let mut it = std::env::args().skip(1);
    while let Some(key) = it.next() {
        let mut value = || it.next().ok_or(format!("missing value for {key}"));
        match key.as_str() {
            "--update" => out.update = value()?.into(),
            "--instructions" => out.instructions = parse_u64(&value()?)?,
            "--chunk" => out.chunk = parse_u64(&value()?)?,
            "--quantum" => out.quantum = parse_u64(&value()?)? as usize,
            "--engine" => {
                out.engine = match value()?.as_str() {
                    "unicorn" => factory::Engine::Unicorn,
                    "hvf" | "hypervisor" => factory::Engine::Hypervisor,
                    other => return Err(format!("unknown engine {other}")),
                }
            }
            "--mode" => {
                out.mode = match value()?.as_str() {
                    "strict" => Mode::Strict,
                    "discovery" => Mode::Discovery,
                    other => return Err(format!("unknown mode {other}")),
                }
            }
            "--start" => out.start = value()?,
            "--image" => {
                let v = value()?;
                let (addr, path) = v.split_once('=').ok_or("--image ADDR=FILE")?;
                out.images.push((parse_u64(addr)?, path.into()));
            }
            "--stop-at" => out.stop_at.push(parse_u64(&value()?)?),
            "--no-stop" => out.stop_at.clear(),
            "--state-out" => out.state_out = Some(value()?.into()),
            "--quiet" => out.quiet = true,
            "--omit" => out.omit.push(value()?),
            "--keep" => {
                let v = value()?;
                out.omit.retain(|o| *o != v);
            }
            "--secondaries" => out.secondaries = true,
            "--set" => {
                // [CORE:]REG=VALUE, e.g. x20=0x14d9b54 or 0:SP_EL1=0xaa000
                let v = value()?;
                let (lhs, val) = v.split_once('=').ok_or("--set [CORE:]REG=VALUE")?;
                let (core, reg) = match lhs.split_once(':') {
                    Some((c, r)) => (Some(parse_u64(c)? as usize), r.to_string()),
                    None => (None, lhs.to_string()),
                };
                out.set_regs.push((core, reg, parse_u64(val)?));
            }
            "--handoff-images" => {
                let dir = PathBuf::from(value()?);
                for (addr, name) in [
                    (0x0u64, "dram_00000000_stage1.bin"),
                    (0x40000, "dram_00040000_image0.bin"),
                    (0x10c0000, "dram_010c0000_ptable.bin"),
                    (0x1101000, "dram_01101000_image4.bin"),
                    (0xf469000, "dram_0f469000_image4_staging.bin"),
                ] {
                    out.images.push((addr, dir.join(name)));
                }
            }
            "--poke" => {
                // ADDR=U32 written to physical memory after the images.
                let v = value()?;
                let (a, val) = v.split_once('=').ok_or("--poke ADDR=VALUE")?;
                out.pokes.push((parse_u64(a)?, parse_u64(val)? as u32));
            }
            "--dump" => {
                // ADDR:LEN hex-dumped from physical memory at the end.
                let v = value()?;
                let (a, l) = v.split_once(':').ok_or("--dump ADDR:LEN")?;
                out.dumps.push((parse_u64(a)?, parse_u64(l)? as usize));
            }
            "--press" => {
                // TIME_MS:KEY[:HOLD_MS], guest time; KEY as in resistor_keys::Key::parse.
                for item in value()?.split(',') {
                    let parts: Vec<&str> = item.split(':').collect();
                    if parts.len() < 2 { return Err("--press TIME_MS:KEY[:HOLD_MS]".into()); }
                    let hold = parts.get(2).map(|h| parse_u64(h)).transpose()?.unwrap_or(150);
                    out.presses.push((parse_u64(parts[0])?, parts[1].to_string(), hold));
                }
            }
            "--all-frames" => out.all_frames = true,
            // Accept a patched update (same size, different hash) for mod testing.
            "--allow-modified" => out.allow_modified = true,
            "--dump-to" => {
                // ADDR:LEN:PATH raw physical memory written to a file at the end.
                let v = value()?;
                let mut it = v.splitn(3, ':');
                let (a, l, p) = (it.next().unwrap_or(""), it.next().ok_or("--dump-to ADDR:LEN:PATH")?, it.next().ok_or("--dump-to ADDR:LEN:PATH")?);
                out.dump_files.push((parse_u64(a)?, parse_u64(l)? as usize, p.into()));
            }
            "--save-snapshot" => out.save_snapshot = Some(value()?.into()),
            "--load-snapshot" => out.load_snapshot = Some(value()?.into()),
            "--policy" => out.policy = Some(value()?),
            "--frames-dir" => out.frames_dir = Some(value()?.into()),
            "--watch" => {
                for part in value()?.split(',') {
                    out.watch.push(parse_u64(part)?);
                }
            }
            "--trace" => out.trace = Some(value()?.into()),
            "--trace-limit" => out.trace_limit = parse_u64(&value()?)? as usize,
            "--trace-after" => out.trace_after_ms = parse_u64(&value()?)?,
            "--watch-range" => {
                for item in value()?.split(',') {
                    let (lo, hi) = item.split_once('-').ok_or("--watch-range LO-HI[,LO-HI]")?;
                    out.watch_ranges.push((parse_u64(lo)?, parse_u64(hi)?));
                }
            }
            other => return Err(format!("unknown option {other}")),
        }
    }
    Ok(out)
}

fn sysreg(name: &str) -> Register {
    Register::Arm64System(arm64::system_register(name).unwrap())
}

fn snapshot(board: &fujimod_emulator::board::Board, core: usize) -> Value {
    let r = |reg| board.read_register(core, reg).map(|v| format!("{v:#x}")).unwrap_or_else(|e| e);
    let mut v = json!({
        "pc": r(Register::Pc),
        "pstate": r(Register::Pstate),
        "sp": r(Register::Sp),
        "x0": r(Register::X(0)), "x1": r(Register::X(1)), "x2": r(Register::X(2)),
        "x19": r(Register::X(19)), "x20": r(Register::X(20)), "x21": r(Register::X(21)),
        "x30": r(Register::X(30)),
    });
    for name in ["VBAR_EL1", "SCTLR_EL1", "SP_EL0", "SP_EL1", "ELR_EL1", "ESR_EL1", "FAR_EL1", "CNTV_CTL_EL0", "CNTV_CVAL_EL0", "0xdf11", "0xdf12", "ICC_PMR_EL1", "ICC_IGRPEN1_EL1", "TPIDR_EL1"] {
        v[name] = json!(r(sysreg(name)));
    }
    v
}

fn run() -> Result<(), String> {
    let args = args()?;
    let resolved = ResolvedConfiguration::bundled(CONFIGURATION)?;
    let selection = &resolved.reference;
    let profile = selection
        .firmware
        .layouts
        .as_ref()
        .and_then(|l| l.profiles.get(PROFILE))
        .ok_or("firmware has no xt5-431 layout profile")?;
    let flash_fact = profile.flash_image.as_ref().ok_or("no flash_image fact")?;

    // Update file -> installed flash image.
    let update = std::fs::read(&args.update).map_err(|e| format!("{}: {e}", args.update.display()))?;
    let expected = selection.firmware.update.as_ref().ok_or("no update identity")?;
    {
        use sha2::{Digest, Sha256};
        let digest = format!("{:x}", Sha256::digest(&update));
        if digest != expected.sha256 {
            if !args.allow_modified || update.len() as u64 != expected.size {
                return Err(format!("update sha256 {digest} != catalog {}", expected.sha256));
            }
            eprintln!("modified update: sha256 {digest} (stock {})", expected.sha256);
        }
    }
    if flash_fact.xor != 0xff {
        return Err("only XOR 0xff flash images are handled".into());
    }
    let flash = fujimod_settings_free_flash(&update, flash_fact.dat_origin)?;

    let ticks_per_second = 1_000_000_000u64;
    let startup = boot::startup_from_profile(&resolved, profile, ticks_per_second)?;

    // Processor starts.
    let starts: Vec<ProcessorStart> = match args.start.as_str() {
        "handoff" => startup
            .processors
            .iter()
            .map(|p| ProcessorStart {
                processor_id: p.processor_id.clone(),
                released: p.released,
                registers: p.registers.clone(),
            })
            .collect(),
        "stage0" => startup
            .processors
            .iter()
            .enumerate()
            .map(|(index, p)| {
                let mpidr = p
                    .registers
                    .iter()
                    .find(|(r, _)| *r == sysreg("MPIDR_EL1"))
                    .map(|(_, v)| *v)
                    .unwrap_or(index as u64);
                ProcessorStart {
                    processor_id: p.processor_id.clone(),
                    released: index == 0 || args.secondaries,
                    registers: vec![
                        (Register::Pc, BOOT_SRAM + 0x800),
                        // EL1h, DAIF masked.
                        (Register::Pstate, 0x3c5),
                        (sysreg("MPIDR_EL1"), mpidr),
                    ],
                }
            })
            .collect(),
        other => return Err(format!("unknown start {other}")),
    };
    let mut starts = starts;
    for (core, reg, value) in &args.set_regs {
        let register = match reg.as_str() {
            "pc" | "PC" => Register::Pc,
            "pstate" | "PSTATE" => Register::Pstate,
            r if r.starts_with('x') => Register::X(r[1..].parse().map_err(|_| format!("bad register {r}"))?),
            r => sysreg(r),
        };
        for (index, start) in starts.iter_mut().enumerate() {
            if core.is_none_or(|c| c == index) {
                start.registers.retain(|(r, _)| *r != register);
                start.registers.push((register, *value));
            }
        }
    }
    let rate = resolved
        .configuration
        .execution
        .as_ref()
        .map(|e| e.instructions_per_tick.clone())
        .ok_or("configuration has no execution policy")?;
    let mut graph = assemble_with_starts(selection, DRAM_LIMIT, rate, Some(ticks_per_second), &starts)?;
    // Execute-in-place: stage0 runs code from the flash aperture, which the
    // flash-storage device cannot serve as instructions. Back the aperture with
    // read-only RAM holding the flash image instead of the device window.
    const FLASH_BASE: u64 = 0xf000_0000;
    const FLASH_SIZE: usize = 0x0800_0000;
    graph.ram.push(factory::Ram { base: FLASH_BASE, size: FLASH_SIZE });
    graph.peripherals.retain(|p| !(p.core < 4 && p.address < DRAM_LIMIT));
    graph.peripherals.retain(|p| !(p.address < FLASH_BASE + FLASH_SIZE as u64 && FLASH_BASE < p.address + p.size as u64));
    // The XP5 catalog declares no A53 memory map; identity-map DRAM and boot SRAM.
    for core in 0..4usize {
        if !graph.mappings.iter().any(|m| m.core == core) {
            for r in graph.ram.iter() {
                graph.mappings.push(factory::MemoryMap { core, address: r.base, physical: r.base, size: r.size, permissions: if r.base == FLASH_BASE { 5 } else { 7 } });
            }
        }
    }
    // Discovery: route every otherwise-unmapped page in the SoC's register
    // space to the bus, which shadows and records unowned MMIO.
    if args.mode == Mode::Discovery {
        const GRANULE: u64 = 0x4000;
        for core in 0..4usize {
            let covered = |page: u64, graph: &factory::Graph| {
                graph.ram.iter().any(|r| page < r.base + r.size as u64 && r.base < page + GRANULE)
                    || graph.peripherals.iter().any(|p| p.core == core && page < p.address + p.size as u64 && p.address < page + GRANULE)
                    || (0xf000_0000..0xf800_0000).contains(&page)
            };
            let mut page = 0xf800_0000u64;
            let mut run: Option<u64> = None;
            let mut adds = vec![];
            while page < 0x1_0000_0000 {
                if covered(page, &graph) {
                    if let Some(start) = run.take() { adds.push((start, page)); }
                } else if run.is_none() {
                    run = Some(page);
                }
                page += GRANULE;
            }
            if let Some(start) = run { adds.push((start, page)); }
            for (start, end) in adds {
                graph.peripherals.push(factory::Peripheral { core, address: start, physical: start, size: (end - start) as usize });
            }
        }
    }
    // The XP5 catalog declares no DMA bus map; give bus masters (and host
    // loading) an identity view of every RAM region.
    if graph.dma_mappings.is_empty() {
        graph.dma_mappings = graph
            .ram
            .iter()
            .map(|r| fujimod_emulator::board::memory::BusMapping::ram(r.base, r.size))
            .collect();
    }
    if std::env::var_os("XT5_DEBUG_GRAPH").is_some() {
        for r in &graph.ram { eprintln!("ram {:#x}+{:#x}", r.base, r.size); }
        for m in &graph.mappings { eprintln!("map core{} {:#x}->{:#x}+{:#x} p{}", m.core, m.address, m.physical, m.size, m.permissions); }
        for m in &graph.dma_mappings { eprintln!("dma {m:?}"); }
        eprintln!("peripherals {}", graph.peripherals.len());
    }

    // Device windows from the SoC profile, minus any we choose to omit.
    let mut windows = boot::windows(selection, "xp5")?;
    let omitted: Vec<String> = windows
        .iter()
        .filter(|w| args.omit.iter().any(|o| *o == w.kind || o.trim_start_matches("imaging-") == w.kind.trim_start_matches("imaging-")))
        .map(|w| format!("{}@{:#x}", w.kind, w.base))
        .collect();
    windows.retain(|w| w.kind != "flash-storage");
    windows.retain(|w| !(w.kind == "unmodeled-bus-drain" && w.base < DRAM_LIMIT));
    windows.retain(|w| !args.omit.iter().any(|o| *o == w.kind || o.trim_start_matches("imaging-") == w.kind.trim_start_matches("imaging-")));
    // The X-T5 configuration declares an empty scene; borrow the sibling X100VI
    // body's imaging frame timing so the imaging blocks have bounded periods.
    {
        let sibling = ResolvedConfiguration::bundled("x100vi-131")?;
        if let Some(fujimod_catalog_configuration::RunScene::Xp5(scene)) = sibling.configuration.scene.as_ref() {
            let mut scene = scene.clone();
            scene.frames.retain(|f| f.block_ids.iter().all(|id| {
                selection.soc.blocks.iter().any(|b| b.id == *id && windows.iter().any(|w| w.base == b.base))
            }));
            boot::apply_run_scene(&resolved, &mut windows, &scene, ticks_per_second)?;
        }
    }
    for w in windows.iter_mut() {
        if matches!(w.kind.as_str(), "imaging-rifp" | "imaging-rifp-io") {
            w.options.entry("completion_us").or_insert(toml_int(1000));
            w.options.entry("source_luma").or_insert(toml_int(128));
        }
        if matches!(w.kind.as_str(), "imaging-preview" | "movdc") {
            w.options.entry("frame_period_us").or_insert(toml_int(1_000_000));
            w.options.entry("source_luma").or_insert(toml_int(128));
        }
        if w.kind == "adc" {
            // configurations/emulator/xt5-431/run.json adc block samples.
            let mut samples = vec![toml_int(2713)];
            samples.extend(std::iter::repeat_n(toml_int(4095), 14));
            w.options.entry("samples").or_insert(toml::Value::Array(samples));
        }
        if w.kind == "pl022" {
            // Line 99 follows the upstream XP5 fixture; the X-T5 wire's parts are unknown.
            w.options.entry("companion_irq_line").or_insert(toml_int(99));
            // The companion selects GPIO port 11 pin 5 (active low) before its
            // first transfer, as on the X100VI; use that body's two endpoints.
            w.options.entry("wire").or_insert(
                toml::Value::try_from(json!({"kind": "gpio-selected", "endpoints": [
                    {"select": {"port": 11, "pin": 5, "active_high": false},
                     "part": {"kind": "bis-configuration-registers", "revision": [3, 12], "idle_high": false}},
                    {"select": {"port": 11, "pin": 3, "active_high": false},
                     "part": {"kind": "lsm6ds-configuration-registers"}}
                ]}))
                .map_err(|e| e.to_string())?,
            );
        }
        if w.kind == "spi-controller" {
            w.options.entry("source_hz").or_insert(toml_int(48_000_000));
            if !w.options.contains_key("endpoints") {
                let block = selection.soc.blocks.iter().find(|b| b.base == w.base).map(|b| b.id.as_str());
                let sink = |port: u32, pin: u32| json!({"select": {"port": port, "pin": pin, "active_high": false},
                                                        "part": {"kind": "generic-sink", "miso_high": false}});
                let endpoints = match block {
                    // Body wiring: spi8 -> power-controller, select GPIO 15/15 active high.
                    // Run inputs: power-controller clock 845151906 s, valid.
                    Some("spi8") => json!([{"select": {"port": 15, "pin": 15, "active_high": true},
                            "part": {"kind": "power-controller", "rtc_seconds": 845151906u32, "rtc_valid": true}}]),
                    // Traced X-T5 chip selects; parts unidentified.
                    Some("spi4") => json!([sink(12, 7)]),
                    Some("spi5") => json!([sink(12, 8)]),
                    // No GPIO select traced (controller-native select, like the X100VI's
                    // imaging serial output): bind to an unused, always-low latch.
                    Some("spi3") => json!([sink(19, 15)]),
                    _ => json!([]),
                };
                w.options.insert("endpoints".into(), toml::Value::try_from(endpoints).map_err(|e| e.to_string())?);
            }
        }
        if w.kind == "flash-storage-controller" {
            // catalog/parts/xt5-serial-nor: jedec_id 2145056 (0x20bb20).
            w.options.entry("jedec_id").or_insert(toml_int(0x20bb20));
        }
        if w.kind == "imaging-resize" {
            w.options.entry("completion_us").or_insert(toml_int(1000));
        }
        if w.kind == "imaging-receiver" {
            w.options.entry("frame_period_us").or_insert(toml_int(1_000_000));
        }
    }
    for w in windows.iter_mut().filter(|w| w.kind == "flash-storage") {
        w.options.insert("erased_tail".into(), toml_int(0xff));
    }
    if std::env::var_os("XT5_DEBUG_WINDOWS").is_some() {
        for w in &windows {
            if !w.options.is_empty() || w.kind.contains("spi") {
                eprintln!("window {} {:#x} {:?}", w.kind, w.base, w.options);
            }
        }
    }
    let mut displays = BTreeMap::new();
    for w in windows.iter().filter(|w| w.kind == "display") {
        displays.insert(w.base, display::Config { period_ns: None, raw_formats: [None; 4] });
    }
    let storage = flash_storage::Storage::new(flash.clone())?;
    let resources = xp5_board::Resources {
        sd: BTreeMap::new(),
        controls: Arc::new(fujimod_emulator_parts_controls::absent::AbsentControls),
        pins: fujimod_emulator_devices::xp5::pins::Pins::shared(),
        clocks: fujimod_emulator_devices::xp5::panel_clocks::Clocks::new(),
        companion: Some(xp5_board::Companion {
            // catalog/soc/xp5 hardware.companion: core4, mailbox lines.
            pins: fujimod_emulator_xp5_io::mailbox::Pins {
                companion: 4,
                request: 55,
                control: 58,
                reply: 141,
                status: 142,
                fault: 143,
            },
            channel: Default::default(),
        }),
        storage: Some(Arc::new(Mutex::new(storage))),
        displays,
    };

    let mut images = vec![];
    if args.start == "stage0" {
        let size = u32::from_le_bytes(flash[0x10..0x14].try_into().unwrap()) as usize;
        images.push(boot::MemoryImage { address: BOOT_SRAM, bytes: flash[..size].to_vec() });
    }
    {
        let mut xip = flash.clone();
        xip.resize(FLASH_SIZE, 0xff);
        images.push(boot::MemoryImage { address: FLASH_BASE, bytes: xip });
    }
    for (address, path) in &args.images {
        let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        images.push(boot::MemoryImage { address: *address, bytes });
    }

    let (mut session, inputs) = boot::open(boot::OpenOptions {
        definition: json!({"bringup": CONFIGURATION}),
        mode: args.mode,
        processors: graph,
        windows,
        controls: fujimod_emulator_xp5_board::ladder_controls::ladder_keys(&resolved)?
            .map(fujimod_emulator_parts_controls::key_input::ControlsOptions::LadderKeys),
        resources,
        engine: args.engine,
        interrupts: startup.interrupts,
        aprofile: startup.aprofile,
        images: vec![],
        scene: None,
    })?;
    for (at_ms, key, hold_ms) in &args.presses {
        let key = fujimod_emulator_xp5_board::session::Key::parse(key)?;
        inputs.key(&mut session, at_ms * 1_000_000, key, true)?;
        inputs.key(&mut session, (at_ms + hold_ms) * 1_000_000, key, false)?;
    }
    let board = &mut session.board;
    eprintln!("opened: omitted {omitted:?}");
    for image in &images {
        // Core 0's view: boot SRAM is not on the DMA bus map.
        board
            .write_physical(image.address, &image.bytes)
            .or_else(|_| board.write_memory(0, image.address, &image.bytes))
            .map_err(|e| format!("image at {:#x}: {e}", image.address))?;
        eprintln!("loaded {:#x} bytes at {:#x}", image.bytes.len(), image.address);
    }

    if let Some(path) = &args.load_snapshot {
        let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let snapshot = session.import_snapshot(&bytes)?;
        session.restore(&snapshot)?;
        eprintln!("restored snapshot {} at t={}", path.display(), session.board.now());
    }
    let board = &mut session.board;
    if let Some(policy) = &args.policy {
        board.set_execution_policy(fujimod_emulator_cpu::ExecutionPolicy::parse(policy)?)?;
    }
    eprintln!("execution policy: {:?}", board.execution_policy());
    for (address, value) in &args.pokes {
        board.write_physical(*address, &value.to_le_bytes()).map_err(|e| format!("poke {address:#x}: {e}"))?;
    }
    // The boot ROM's register-init table, applied before the loader runs.
    if args.start == "stage0" {
        let count = u32::from_le_bytes(flash[0x14..0x18].try_into().unwrap()) as usize;
        for i in 0..count {
            let at = 0x18 + i * 8;
            let address = u32::from_le_bytes(flash[at..at + 4].try_into().unwrap()) as u64;
            let value = u32::from_le_bytes(flash[at + 4..at + 8].try_into().unwrap());
            match board.write_physical(address, &value.to_le_bytes()) {
                Ok(()) => eprintln!("init {address:#x} <- {value:#x}"),
                Err(e) => eprintln!("init {address:#x} <- {value:#x} FAILED: {e}"),
            }
        }
    }

    if !args.watch.is_empty() {
        let mut w = args.watch.clone();
        w.sort_unstable();
        w.dedup();
        board.watch_pcs(&w)?;
    }
    if !args.watch_ranges.is_empty() {
        board.transaction_watch_begin(args.watch_ranges.clone(), args.trace_limit)?;
    }
    let mut tracing = false;
    if args.trace.is_some() && args.trace_after_ms == 0 && args.watch_ranges.is_empty() {
        board.observe_transactions(Some(args.trace_limit));
        tracing = true;
    }
    let cores = 4usize;
    let started = Instant::now();
    let mut ran = 0u64;
    let mut result = Ok(());
    let mut last_pcs = vec![0u64; cores];
    let mut stall = 0u32;
    let mut latest: BTreeMap<usize, fujimod_emulator_devices::graphics::scanout::Frame> = BTreeMap::new();
    let mut frame_count: BTreeMap<usize, u64> = BTreeMap::new();
    'outer: while ran < args.instructions {
        let step = args.chunk.min(args.instructions - ran);
        if let Err(e) = board.run_for_instructions(step, args.quantum) {
            result = Err(e);
            break;
        }
        ran += step;
        if !tracing && args.watch_ranges.is_empty() && args.trace.is_some() && board.now() >= args.trace_after_ms * 1_000_000 {
            board.observe_transactions(Some(args.trace_limit));
            tracing = true;
            eprintln!("tracing from t={}", board.now());
        }
        for frame in board.take_frames() {
            *frame_count.entry(frame.output).or_default() += 1;
            if let (true, Some(dir)) = (args.all_frames, &args.frames_dir) {
                std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
                let rgb: Vec<u8> = frame.rgba.chunks_exact(4).flat_map(|p| [p[0], p[1], p[2]]).collect();
                let png = fujimod_recording::Frame::rgb(frame.width, frame.height, rgb)?.png().map(|p| p.to_vec())?;
                let path = dir.join(format!("output{}-seq{:04}-t{}ms.png", frame.output, frame.sequence, board.now() / 1_000_000));
                std::fs::write(&path, png).map_err(|e| e.to_string())?;
            }
            latest.insert(frame.output, frame);
        }
        for line in board.take_console() {
            println!("console: {line}");
        }
        let pcs: Vec<u64> = (0..cores)
            .map(|c| board.read_register(c, Register::Pc).unwrap_or(0))
            .collect();
        if !args.quiet {
            let counts = board.instruction_counts();
            eprintln!(
                "[{:>12}] pcs {} counts {:?} t={}",
                ran,
                pcs.iter().map(|p| format!("{p:#x}")).collect::<Vec<_>>().join(" "),
                counts,
                board.now()
            );
        }
        for (core, pc) in pcs.iter().enumerate() {
            if args.stop_at.contains(pc) {
                eprintln!("core {core} reached stop address {pc:#x}");
                break 'outer;
            }
        }
        if pcs == last_pcs {
            stall += 1;
            if stall >= 5 {
                eprintln!("PCs unchanged for 5 chunks; stopping");
                break;
            }
        } else {
            stall = 0;
        }
        last_pcs = pcs;
    }
    let elapsed = started.elapsed();
    for (address, len, path) in &args.dump_files {
        let mut bytes = vec![0u8; *len];
        board.read_physical(*address, &mut bytes).map_err(|e| format!("dump {address:#x}: {e}"))?;
        std::fs::write(path, &bytes).map_err(|e| format!("{}: {e}", path.display()))?;
        eprintln!("dumped {len:#x} bytes at {address:#x} to {}", path.display());
    }
    for (address, len) in &args.dumps {
        let mut bytes = vec![0u8; *len];
        match board.read_physical(*address, &mut bytes) {
            Ok(()) => {
                for (i, chunk) in bytes.chunks(16).enumerate() {
                    let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
                    eprintln!("dump {:#012x}: {}", address + (i * 16) as u64, hex.join(" "));
                }
            }
            Err(e) => eprintln!("dump {address:#x}: {e}"),
        }
    }
    let state = board.state();
    let report = json!({
        "result": match &result { Ok(()) => "ok".to_string(), Err(e) => e.clone() },
        "instructions": ran,
        "seconds": elapsed.as_secs_f64(),
        "guest_time": board.now(),
        "cores": (0..cores).map(|c| snapshot(board, c)).collect::<Vec<_>>(),
        "failure": state.get("failure"),
        "unmodeled_system": state.get("unmodeled_system"),
        "released": state.get("released"),
        "watched": board.pc_entries().iter().map(|e| json!({
            "core": e["core"], "pc": format!("{:#x}", e["pc"].as_u64().unwrap_or(0)),
            "x0_3": e["arguments"].as_array().map(|a| a.iter().map(|v| format!("{:#x}", v.as_u64().unwrap_or(0))).collect::<Vec<_>>()),
            "tick": e["tick"],
        })).collect::<Vec<_>>(),
        "waiting": state.get("waiting"),
    });
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
    if let Some(dir) = &args.frames_dir {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        for (output, frame) in &latest {
            let rgb: Vec<u8> = frame.rgba.chunks_exact(4).flat_map(|p| [p[0], p[1], p[2]]).collect();
            let png = fujimod_recording::Frame::rgb(frame.width, frame.height, rgb)?.png().map(|p| p.to_vec())?;
            let path = dir.join(format!("output{output}.png"));
            std::fs::write(&path, png).map_err(|e| e.to_string())?;
            eprintln!("frame output {output}: {}x{} seq {} -> {}", frame.width, frame.height, frame.sequence, path.display());
        }
    }
    eprintln!("frames per output: {frame_count:?}");
    if let Ok(kinds) = std::env::var("XT5_DEVICE_STATES") {
        for kind in kinds.split(',') {
            eprintln!("device {kind}: {}", serde_json::to_string(&board.device_states(kind)?).unwrap());
        }
    }
    if let Ok(path) = std::env::var("XT5_GIC_OUT") {
        std::fs::write(&path, serde_json::to_string_pretty(&board.gic_state()?).unwrap()).map_err(|e| e.to_string())?;
    }
    if !args.watch_ranges.is_empty() {
        let batch = board.transaction_watch_end()?;
        let path = args.trace.clone().unwrap_or_else(|| "watch.json".into());
        std::fs::write(&path, serde_json::to_string(&batch).unwrap()).map_err(|e| e.to_string())?;
        eprintln!("watch: {} transactions, {} omitted -> {}", batch.transactions.len(), batch.omitted, path.display());
    } else if let Some(path) = &args.trace {
        std::fs::write(path, serde_json::to_string(&board.transactions()).unwrap())
            .map_err(|e| format!("{}: {e}", path.display()))?;
    }
    if let Some(path) = &args.state_out {
        std::fs::write(path, serde_json::to_string_pretty(&state).unwrap())
            .map_err(|e| format!("{}: {e}", path.display()))?;
    }
    if let Some(path) = &args.save_snapshot {
        if result.is_ok() {
            let bytes = session.checkpoint(None)?.export()?;
            std::fs::write(path, &bytes).map_err(|e| format!("{}: {e}", path.display()))?;
            eprintln!("saved snapshot {} ({} bytes)", path.display(), bytes.len());
        } else {
            eprintln!("not saving a snapshot of a failed run");
        }
    }
    Ok(())
}

fn toml_int(v: i64) -> toml::Value {
    toml::Value::Integer(v)
}

fn fujimod_settings_free_flash(update: &[u8], origin: u64) -> Result<Vec<u8>, String> {
    let origin = usize::try_from(origin).map_err(|_| "flash origin overflow")?;
    let installed = update.get(origin..).ok_or("update shorter than flash origin")?;
    Ok(fujimod_firmware::invert(installed))
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
