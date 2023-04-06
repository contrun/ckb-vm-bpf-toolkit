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
from elfutils import get_function_address_range
from bcc import BPF, USDT
import ctypes
import re

from elftools.elf.elffile import ELFFile

elf = ELFFile(open(locate_bin(), "rb"))

func_name = extract_bpf_arg("func")
regs = extract_bpf_arg("regs").split(",")

func_range = get_function_address_range(elf, func_name)
if func_range is None:
  print("Range for function %s not found" % (func_name))
  exit(1)

func_name, func_low_pc, func_high_pc = func_range[0], func_range[1], func_range[2]

print("Profiling func %s" % (func_name))

bpf_text = """
#include "riscv.h"

BPF_HASH(stats, uint64_t);
BPF_HASH(instruction_end_stats, uint64_t);
BPF_HASH(return_value);

@@DEFS@@

int do_execute(struct pt_regs *ctx) {
    uint64_t pc;
    bpf_usdt_readarg(1, ctx, &pc);

    if (pc != @@PC@@) {
      return 0;
    }

    uint64_t regs_addr;
    bpf_usdt_readarg(4, ctx, &regs_addr);

    uint64_t mem_addr;
    bpf_usdt_readarg(5, ctx, &mem_addr);

    stats.increment(1);

    @@ACTIONS@@

    return 0;
}

int do_execute_end(struct pt_regs *ctx) {
    uint64_t pc;
    bpf_usdt_readarg(1, ctx, &pc);

    uint64_t current_instruction;
    bpf_usdt_readarg(3, ctx, &current_instruction);

    if (pc < @@PC@@ || pc >= @@HIGH_PC@@) {
      return 0;
    }

    // 0x101000027 is the JALR with rs1 set to RA
    if (current_instruction != 0x101000027) {
      return 0;
    }

    uint64_t regs_addr;
    bpf_usdt_readarg(4, ctx, &regs_addr);

    uint64_t mem_addr;
    bpf_usdt_readarg(5, ctx, &mem_addr);

    uint64_t ret;
    bpf_probe_read_user(&ret, sizeof(uint64_t), (void *)(regs_addr + 8 * A0));

    instruction_end_stats.increment(1);

    uint64_t value = 0;
    return_value.lookup_or_try_init(&ret, &value);
    value = value+1;
    return_value.update(&ret, &value);

    return 0;
}
"""

bpf_text = bpf_text.replace("@@PC@@", str(func_low_pc)).replace("@@HIGH_PC@@", str(func_high_pc))

def_text = "\n".join(map(lambda reg: "BPF_HASH(hash_%s);\nBPF_HASH(hash_mem_%s);" % (reg, reg), regs))
action_text = "\n".join(map(lambda reg: """
uint64_t reg_{reg};
bpf_probe_read_user(&reg_{reg}, sizeof(uint64_t), (void *)(regs_addr + 8 * {reg_up}));
uint64_t mem_{reg};
bpf_probe_read_user(&mem_{reg}, sizeof(uint64_t), (void *)(mem_addr + reg_{reg}));
hash_{reg}.increment(reg_{reg});
hash_mem_{reg}.update(&reg_{reg}, &mem_{reg});
""".format(reg=reg, reg_up=reg.upper()), regs))

bpf_text = bpf_text.replace("@@DEFS@@", def_text).replace("@@ACTIONS@@", action_text)
print(bpf_text)

p = build_debugger_process()

u = USDT(pid=int(p.pid))
u.enable_probe(probe="ckb_vm:execute_inst", fn_name="do_execute")
u.enable_probe(probe="ckb_vm:execute_inst_end", fn_name="do_execute_end")
include_path = os.path.join(
  os.path.dirname(os.path.abspath(__file__)), "..", "bpfc")
b = BPF(text=bpf_text, usdt_contexts=[u], cflags=["-Wno-macro-redefined", "-I", include_path])

p.communicate(input="\n".encode())
print()
print()

called = b["stats"][ctypes.c_ulong(1)].value
print("Func %s has been called %s times!" % (func_name, called))
called = b["instruction_end_stats"][ctypes.c_ulong(1)].value
print("Func end %s has been called %s times!" % (func_name, called))

for k, v in sorted(b.get_table("return_value").items(), key=lambda kv: kv[0].value):
    print(f"key: {k.value:016x}, value: {v.value:}")

for reg in regs:
  table_name = "hash_%s" % (reg)
  print("Stats for %s:" % (table_name))
  table = b.get_table(table_name)
  count = sum([v.value for _, v in table.items()])
  print("count: ", count)
  possibly_double_freed = [k for k, v in table.items() if v.value > 1 and k.value != 0]
  for k, v in sorted(table.items(), key=lambda kv: kv[0].value):
      if v.value > 1 and k.value != 0:
          print(f"key: {k.value:016x}, value: {v.value:}")
  table_name = "hash_mem_%s" % (reg)
  print("Stats for %s:" % (table_name))
  table = b.get_table(table_name)
  for k in possibly_double_freed:
      print(k, table[k])
