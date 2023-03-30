#!/usr/bin/env python3

# Trace a specific function, and optionally sample the value of specified registers
#
# Usage:
# functrace.py --bpf-func <func name to trace> --bpf-regs <regs to use> <other arguments...>
#
# For example:
# functrace.py --bpf-func __rg_alloc --bpf-regs a1 --bin binaryfile

import sys
import os
sys.path.append(os.path.join(
  os.path.dirname(os.path.abspath(__file__)), "..", "contrib"))

from debugger import build_debugger_process, locate_bin, extract_bpf_arg
from bcc import BPF, USDT
import ctypes
import re

from elftools.elf.elffile import ELFFile

elf = ELFFile(open(locate_bin(), "rb"))

func_name = extract_bpf_arg("func")
regs = extract_bpf_arg("regs").split(",")

symtab = elf.get_section_by_name(".symtab")

entries = list(filter(lambda symbol: (re.search(func_name, symbol.name)) and
                                     (symbol.entry.st_info.type == "STT_FUNC"),
                      symtab.iter_symbols()))

if len(entries) > 1:
  print("There is more than one entry matching %s, please include more chars to narrow down the search:" % (func_name))
  for entry in entries:
    print(entry.name)
  exit(1)

func_name = entries[0].name
address = entries[0].entry.st_value

print("Profiling func %s" % (func_name))

bpf_text = """
#include "riscv.h"

BPF_HASH(stats, uint64_t);

@@DEFS@@

int do_execute(struct pt_regs *ctx) {
    uint64_t pc;
    bpf_usdt_readarg(1, ctx, &pc);

    if (pc != @@PC@@) {
      return 0;
    }

    uint64_t regs_addr;
    bpf_usdt_readarg(4, ctx, &regs_addr);
    stats.increment(1);

    @@ACTIONS@@

    return 0;
}
"""

bpf_text = bpf_text.replace("@@PC@@", str(address))

def_text = "\n".join(map(lambda reg: "BPF_HISTOGRAM(histo_%s);" % (reg), regs))
action_text = "\n".join(map(lambda reg: """
uint64_t reg_{reg};
bpf_probe_read_user(&reg_{reg}, sizeof(uint64_t), (void *)(regs_addr + 8 * {reg_up}));
histo_{reg}.increment(bpf_log2l(reg_{reg}));
""".format(reg=reg, reg_up=reg.upper()), regs))

bpf_text = bpf_text.replace("@@DEFS@@", def_text).replace("@@ACTIONS@@", action_text)

p = build_debugger_process()

u = USDT(pid=int(p.pid))
u.enable_probe(probe="ckb_vm:execute_inst", fn_name="do_execute")
include_path = os.path.join(
  os.path.dirname(os.path.abspath(__file__)), "..", "bpfc")
b = BPF(text=bpf_text, usdt_contexts=[u], cflags=["-Wno-macro-redefined", "-I", include_path])

p.communicate(input="\n".encode())
print()
print()

called = b["stats"][ctypes.c_ulong(1)].value
print("Func %s has been called %s times!" % (func_name, called))

for reg in regs:
  print("Stats for %s:" % (reg))
  b["histo_%s" % (reg)].print_log2_hist(reg)
