#!/usr/bin/env python3
"""Запуск статического ARM-ELF теста (abi-smoke) без qemu: Unicorn + разбор ELF руками.

Используется tests/run.sh, когда qemu-arm недоступен; нужны python3 с pyelftools и unicorn.

В тесте все сисколлы ядра подменены (open/read/write/socket/... — свои функции), поэтому эмулятору
достаточно обработать svc: exit (1) и write (4) в stdout.
"""
import sys
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_INTR, UC_HOOK_MEM_UNMAPPED
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R7, UC_ARM_REG_SP, UC_ARM_REG_PC, UC_ARM_REG_LR

STACK_BASE, STACK_SIZE = 0x7f000000, 0x100000
EXIT_CODE = [None]
OUT = [b""]


def load(path):
    with open(path, "rb") as fh:
        elf = ELFFile(fh)
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        mmap_ranges = []
        for seg in elf.iter_segments():
            if seg["p_type"] != "PT_LOAD":
                continue
            vaddr, filesz, memsz = seg["p_vaddr"], seg["p_filesz"], seg["p_memsz"]
            base = vaddr & ~0xFFF
            end = (vaddr + memsz + 0xFFF) & ~0xFFF
            uc.mem_map(base, end - base)
            uc.mem_write(vaddr, seg.data())
            mmap_ranges.append((vaddr, vaddr + memsz))
        uc.mem_map(STACK_BASE, STACK_SIZE)
        uc.reg_write(UC_ARM_REG_SP, STACK_BASE + STACK_SIZE - 16)
        entry = elf.header["e_entry"]

    def on_intr(u, intno, user):
        pc = u.reg_read(UC_ARM_REG_PC)
        # svc #0: двухбайтовая инструкция, к моменту хука PC уже на следующей
        r7 = u.reg_read(UC_ARM_REG_R7)
        if r7 == 1:  # exit(status)
            EXIT_CODE[0] = u.reg_read(UC_ARM_REG_R0)
            u.emu_stop()
            return
        if r7 == 4:  # write(fd, buf, len) — в тесте это отчёт
            buf, ln = u.reg_read(UC_ARM_REG_R1), u.reg_read(UC_ARM_REG_R2)
            data = u.mem_read(buf, ln)
            OUT[0] += bytes(data)
            u.reg_write(UC_ARM_REG_R0, ln)
            return
        raise RuntimeError(f"unexpected svc {r7} at 0x{pc:x}")

    def on_unmapped(u, access, addr, size, value, user):
        print(f"!! unmapped {access} at 0x{addr:x} pc=0x{u.reg_read(UC_ARM_REG_PC):x}")
        return False

    uc.hook_add(UC_HOOK_INTR, on_intr)
    uc.hook_add(UC_HOOK_MEM_UNMAPPED, on_unmapped)
    return uc, entry


def main(path):
    uc, entry = load(path)
    uc.emu_start(entry, 0, timeout=120 * 10**6, count=200_000_000)
    sys.stdout.write(OUT[0].decode("utf-8", "replace"))
    code = EXIT_CODE[0]
    if code is None:
        print(f"!! не завершился (PC=0x{uc.reg_read(UC_ARM_REG_PC):x})")
        return 99
    if code:
        print(f"!! строка {code}")
    return 1 if code else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
