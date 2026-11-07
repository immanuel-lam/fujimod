#!/usr/bin/env python3
"""Emulator-only patches for an X-T5 SD startup card.

  xt5_card_emu_patch.py CARD_DIR OUT_DIR OFFSET=HEXWORD [OFFSET=HEXWORD ...]

Copies CARD_DIR to OUT_DIR, replaces 32-bit words in ffboot.bin at the given
RAM offsets, and rewrites the ffboot.bin CRC32 that marble_init.bin's loader
request block carries (fujimod-recovery xp5-sd-loader `setup_sd_request`, word 2;
standard reflected CRC-32, same as zlib.crc32).

The X-T5 stage1 (reset stage, RAM 0) programs GICv3 EL3/EL2 system registers
that the emulator's CPU backend does not implement. These patches NOP them for
the emulator run only; a real card must carry the unpatched image.
"""
import os
import shutil
import struct
import sys
import zlib

LOADER = 0x18000            # xp5-sd-loader image offset inside marble_init.bin
REQUEST = 0x39e8            # setup_sd_request symbol offset inside the loader


def main():
    src, out = sys.argv[1], sys.argv[2]
    os.makedirs(out, exist_ok=True)
    for name in os.listdir(src):
        if name != 'ffboot.bin' and name != 'marble_init.bin':
            if not os.path.exists(os.path.join(out, name)):
                shutil.copy(os.path.join(src, name), os.path.join(out, name))
    ff = bytearray(open(os.path.join(src, 'ffboot.bin'), 'rb').read())
    for item in sys.argv[3:]:
        off, word = item.split('=')
        off, word = int(off, 0), int(word, 16)
        old = struct.unpack_from('<I', ff, off)[0]
        struct.pack_into('<I', ff, off, word)
        print(f'ffboot.bin +{off:#x}: {old:#010x} -> {word:#010x}')
    m = bytearray(open(os.path.join(src, 'marble_init.bin'), 'rb').read())
    req = LOADER + REQUEST
    assert struct.unpack_from('<Q', m, req)[0] == 1 and struct.unpack_from('<Q', m, req + 8)[0] == len(ff)
    crc = zlib.crc32(bytes(ff)) & 0xFFFFFFFF
    print(f'crc32 {struct.unpack_from("<Q", m, req + 16)[0]:#x} -> {crc:#x}')
    struct.pack_into('<Q', m, req + 16, crc)
    open(os.path.join(out, 'ffboot.bin'), 'wb').write(ff)
    open(os.path.join(out, 'marble_init.bin'), 'wb').write(m)


if __name__ == '__main__':
    main()
