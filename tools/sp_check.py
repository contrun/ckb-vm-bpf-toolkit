#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.join(
  os.path.dirname(os.path.abspath(__file__)), "..", "contrib"))

from debugger import build_debugger_process, locate_bin
from bcc import BPF, USDT
import ctypes

from elftools.elf.elffile import ELFFile

elf = ELFFile(open(locate_bin(), "rb"))

# Iterate through program headers for the maximum address touched by PT_LOAD
elf_end = 0
for segment in elf.iter_segments():
  if segment.header.p_type == "PT_LOAD":
    current_end = segment.header.p_vaddr + segment.header.p_memsz
    if current_end > elf_end:
      elf_end = current_end

bpf_text = """
#include "riscv.h"

BPF_HASH(stats, uint64_t);

int do_execute(struct pt_regs *ctx) {
    uint64_t regs_addr;
    bpf_usdt_readarg(4, ctx, &regs_addr);
    uint64_t sp;
    bpf_probe_read_user(&sp, sizeof(uint64_t), (void *)(regs_addr + 8 * SP));

    uint64_t maximum = 0xFFFFFFFFFFFFFFFF, *val, key = 1;
    val = stats.lookup_or_try_init(&key, &maximum);
    if (val) {
      if (sp < *val) {
        *val = sp;
      }
    }

    return 0;
}
"""

p = build_debugger_process()

u = USDT(pid=int(p.pid))
u.enable_probe(probe="ckb_vm:execute_inst", fn_name="do_execute")
include_path = os.path.join(
  os.path.dirname(os.path.abspath(__file__)), "..", "bpfc")
b = BPF(text=bpf_text, usdt_contexts=[u], cflags=["-Wno-macro-redefined", "-I", include_path])

p.communicate(input="\n".encode())
print()
print()

print("   ELF End: 0x{:x}".format(elf_end))
sp = b["stats"][ctypes.c_ulong(1)].value
print("Minimal SP: 0x{:x}".format(sp))

if sp - elf_end <= 0x1000:
  print("WARNING: Minimal SP is only less than a page larger than ELF end!")
