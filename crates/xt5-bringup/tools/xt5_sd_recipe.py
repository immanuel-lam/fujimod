#!/usr/bin/env python3
"""Hand-authored X-T5 4.31 XP5 recovery recipe (dual-boot startup card only).

  xt5_sd_recipe.py UPDATE.DAT [FIRMWARE_ID] [--write CATALOG_JSON]

Prints the recipe entry for `fujimod-recovery` and, with --write, replaces or
appends it in catalog/recovery/recipes.generated.json.

Located facts (X-T5 4.31, FWUP0030.DAT, type-6 container, flash origin 628):
  setup prefix     DAT 628 (0x274), 0x40000 bytes; header word 0x10 = 0x12000
  bootstrap        prefix+0x850 (SRAM 0xff800050), gate at +0x878 (ldr x30; ret)
  continuation     0xf0027190 (flash aperture park code)
  initializer      SRAM 0xff800088 (prefix+0x888), 940 bytes
  delay            SRAM 0xff801108 (prefix+0x1908), 160 bytes (identical to X-M5 1.30)
  stack            0xff815800 (adr x1 + 0x4000 at prefix+0x868)
  reset stage      flash 0x28000 (DAT 0x28274), stage0 DMA-copies 0x14000 bytes to DRAM 0
  selector         stage1 u64 at offset 0x11a00: 1 = load images from flash,
                   0 = images already in DRAM (stage1 0x24c4/0x2590/0x25d0)
  partition table  flash 0x1a0000 -> DRAM 0x10c0000 (stage1 0x269c)
  flash pins       stage0 0xff810b08..0xff810b70 writes 0xff90b000..0xff90b014

Not located for the X-T5 (conservative choices, see `missing`):
  status lamp      X-M5 1.30 values are copied; unverified on the X-T5 body
  SD pad routing   no operations emitted; the real card read would fail safely
  updater          not located; `build` (recovery card with DAT) refuses
  p3               no fixed DRAM address; the M4 payload is not preloaded
  p6               overlays placed at DRAM 0x4e70000 as observed in the flash boot
"""
import hashlib
import json
import os
import struct
import sys

ORIGIN = 628
PREFIX = 0x40000
BASE = 0xFF800000
PT_FLASH = 0x1A0000
PT_DRAM = 0x10C0000
STAGE1_FLASH, STAGE1_SIZE = 0x28000, 0x14000
SELECTOR = 0x11A00
OVERLAYS_DRAM = 0x4E70000

sys.path.insert(0, os.path.expanduser('~/xt5work/tools'))
import fwpatch  # noqa: E402  (the user's LZ tokenizer; same stream format as fujimod method4)


def sha(b):
    return hashlib.sha256(b).hexdigest()


def source(dat_offset, data, compression='raw', decoded=None):
    return dict(dat_offset=dat_offset, size=len(data), compression=compression,
                decoded_size=len(decoded if decoded is not None else data),
                sha256=sha(decoded if decoded is not None else data))


def partitions(flash):
    pt = flash[PT_FLASH:PT_FLASH + 0x800]
    off = struct.unpack_from('<Q', pt, 0)[0] - PT_DRAM
    out = {}
    while True:
        pid = struct.unpack_from('<I', pt, off)[0]
        if pid == 0xFFFFFFFF:
            break
        f = struct.unpack_from('<QQQQQQIIQ', pt, off)
        out[f[0]] = dict(dram=f[1], size=f[2], zero_start=f[3], zero_size=f[4],
                         flash=f[5], flash_size=f[6], flags=f[8])
        off += 0x40
    return out


def main():
    dat_path = sys.argv[1]
    firmware_id = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].startswith('--') else 'xt5-431'
    write = sys.argv[sys.argv.index('--write') + 1] if '--write' in sys.argv else None
    dat = open(dat_path, 'rb').read()
    flash = fwpatch.invert(dat[ORIGIN:])
    assert struct.unpack_from('<I', dat, 0)[0] == 6, 'expected a type-6 update container'
    prefix = flash[:PREFIX]
    assert struct.unpack_from('<I', prefix, 0x10)[0] == 0x12000, 'setup length differs'
    assert prefix[0x850:0x854] == bytes.fromhex('df4303d5'), 'bootstrap differs'
    assert struct.unpack_from('<I', prefix, 0x878)[0] & 0xFF00001F == 0x5800001E
    assert struct.unpack_from('<Q', flash, STAGE1_FLASH + SELECTOR)[0] == 1, 'selector differs'

    plan_regions = [
        ('reset stage', 0, source(ORIGIN + STAGE1_FLASH, flash[STAGE1_FLASH:STAGE1_FLASH + STAGE1_SIZE])),
        ('partition table', PT_DRAM, source(ORIGIN + PT_FLASH, flash[PT_FLASH:PT_FLASH + 0x800])),
    ]
    bss = []
    for pid, p in sorted(partitions(flash).items()):
        if pid == 6 and p['dram'] == 0 and p['size']:
            # Overlays: no table address; the flash-boot emulator run places the
            # decoded image at DRAM 0x4e70000 (observed, not located in code).
            p = p | {'dram': OVERLAYS_DRAM, 'zero_size': 0}
        if p['dram'] == 0 or p['size'] == 0:
            continue
        if p['flags'] & 1:
            dsize, csize, nblk, stream = fwpatch.lz_partition(flash, p | {'flash': p['flash'], 'size': p['size']})
            decoded, _, _ = fwpatch.tokenize(stream, dsize)
            packed = struct.unpack_from('<I', flash, p['flash'] + 4)[0]
            size = min(-(-packed // 0x4000) * 0x4000, p['flash_size'])
            src = source(ORIGIN + p['flash'], flash[p['flash']:p['flash'] + size], 'method4', bytes(decoded))
        else:
            src = source(ORIGIN + p['flash'], flash[p['flash']:p['flash'] + p['size']])
        plan_regions.append((f'partition{pid}', p['dram'], src))
        if p['zero_size']:
            bss.append(dict(name=f'partition{pid}', address=p['zero_start'], size=p['zero_size']))
    end = max([r[1] + r[2]['decoded_size'] for r in plan_regions] + [b['address'] + b['size'] for b in bss])
    plan = dict(size=-(-end // 0x1000) * 0x1000, entry=0,
                regions=[dict(name=n, address=a, source=s) for n, a, s in plan_regions],
                bss=bss,
                edits=[dict(address=SELECTOR, old=1, new=0,
                            what='stage1: images already in DRAM, skip the flash loads (0x11a00)')])

    init_size = 940
    xp5 = dict(
        prefix=source(ORIGIN, prefix),
        low_length=0x12000, length_flags=0, base=BASE, stack=0xFF815800,
        bootstrap_offset=0x850, initialize_offset=0x888, gate_offset=0x878,
        continuation=0xF0027190,
        initializer=dict(address=BASE + 0x88, size=init_size, sha256=sha(prefix[0x888:0x888 + init_size])),
        delay=dict(address=BASE + 0x1108, size=160, sha256=sha(prefix[0x1908:0x1908 + 160])),
        reset_dat=ORIGIN + STAGE1_FLASH, reset_copy_size=STAGE1_SIZE, selector=SELECTOR,
        flash=dict(controller=0xFF90A000, aperture=0xF0000000, window_mask=0xF8000000,
                   clock=0xFFA19040, clock_commit=0xFFA19080,
                   pins=[dict(address=0xFF90B000 + 4 * i, value=v) for i, v in
                         enumerate([0x20002, 0xF000F, 0x3FFF3FFF, 0x55055505, 0x1550155, 0x3FF23FF2])]),
        # UNVERIFIED on the X-T5: copied from the X-M5 1.30 recipe.
        lamp=dict(pio_base=0xFF907000, clock_address=0xFF90C318, clock_mask=0x20000,
                  reset_address=0xFF90C92C, reset_mask=0x10000, green_port=8, red_port=6, pin=2),
        # SD host base from the X-M5/X100VI recipes; pad routing not located.
        board=dict(host=0xFF9B0000, timeout_setting=14, operations=[]),
        proofs=[
            dict(source=source(ORIGIN, prefix), offset=0x850, size=48, sha256=sha(prefix[0x850:0x880])),
            dict(source=source(ORIGIN, prefix), offset=0x11308, size=0x6C, sha256=sha(prefix[0x11308:0x11374])),
        ],
        banks=dict(copies=[], edits=[]),
    )
    recipe = dict(
        firmware_id=firmware_id, source_size=len(dat), updater=None, source_sha256=sha(dat),
        update_filename='FWUP0030.DAT', generation='xp5', plan=plan, packaging=None, exr=None,
        setup=None, xp5=xp5, cold_start=None, file_api=None,
        sd_boot=dict(hold=[dict(id='front_command_dial.press'), dict(id='rear_command_dial.press')]),
        firmware_update=None,
        missing=[
            'version-independent stock updater acceptance',
            'X-T5 status-lamp GPIO binding unverified (X-M5 1.30 values copied)',
            'X-T5 SD pad routing operations not located (none emitted)',
            'partition 3 (M4 payload) has no fixed DRAM address and is not preloaded',
            'partition 6 address 0x4e70000 observed in the emulator flash boot, not located in code',
        ],
    )
    if write:
        entries = json.load(open(write))
        entries = [e for e in entries if e['firmware_id'] != firmware_id] + [recipe]
        json.dump(entries, open(write, 'w'), indent=2)
        open(write, 'a').write('\n')
        print(f'wrote {firmware_id} to {write}')
    else:
        print(json.dumps(recipe, indent=1))
    for n, a, s in plan_regions:
        print(f'{n:16} dram {a:#10x} dat {s["dat_offset"]:#10x} size {s["size"]:#9x} decoded {s["decoded_size"]:#9x} {s["compression"]}', file=sys.stderr)
    print(f'plan size {plan["size"]:#x}', file=sys.stderr)


if __name__ == '__main__':
    main()
