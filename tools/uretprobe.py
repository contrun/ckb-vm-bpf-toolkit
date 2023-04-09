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

BPF_HASH(num_of_effective_jumps, uint64_t);
BPF_HASH(num_of_calling, uint64_t);
BPF_HASH(num_of_returning, uint64_t);
BPF_HASH(return_values, uint64_t);
// hash map that maps the link addresses to the reference counts
BPF_HASH(jump_from_addresses, uint64_t);

@@DEFS@@

int do_jump(struct pt_regs *ctx) {
    // Initialize link, so that bpf verifier does not report error like R8 !read_ok
    uint64_t link = 0;
    bpf_usdt_readarg(1, ctx, &link);

    uint64_t next_pc;
    bpf_usdt_readarg(2, ctx, &next_pc);

    // x calls a, link = current address in x, next_pc = start address of a
    // y returns to a, link = x0, next_pc = some address of a

    int is_calling = 0;
    int is_returning = 0;
    if (next_pc == @@PC@@ && link != 0) {
        // Initialize reference of the link, increment refcount if neccesary. 
        jump_from_addresses.increment(link);
        is_calling = 1;
    }

    if (next_pc >= @@PC@@ && next_pc < @@HIGH_PC@@) {
        if (link == 0) {
            // Should be unreachable
            return 1;
        }
        uint64_t *refcount = jump_from_addresses.lookup(&link);
        if (refcount == NULL) {
            // Should be unreachable
            return 1;
        }
        (*refcount)--;
        if (*refcount == 0) {
            jump_from_addresses.delete(&link);
        }
        is_returning = 1;
    }

    if (is_returning == 0 && is_calling == 0) {
        return 0;
    }

    uint64_t regs_addr;
    bpf_usdt_readarg(3, ctx, &regs_addr);

    uint64_t mem_addr;
    bpf_usdt_readarg(4, ctx, &mem_addr);

    num_of_effective_jumps.increment(1);
    if (is_calling == 1) {
        num_of_calling.increment(1);
    }
    if (is_returning == 1) {
        uint64_t ret;
        bpf_probe_read_user(&ret, sizeof(uint64_t), (void *)(regs_addr + 8 * A0));

        uint64_t zero_value = 0;
        return_values.lookup_or_try_init(&ret, &zero_value);
        return_values.increment(ret);
    }

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
u.enable_probe(probe="ckb_vm:jump", fn_name="do_jump")
include_path = os.path.join(
  os.path.dirname(os.path.abspath(__file__)), "..", "bpfc")
b = BPF(text=bpf_text, usdt_contexts=[u], cflags=["-Wno-macro-redefined", "-I", include_path])

p.communicate(input="\n".encode())
print()
print()

called = b["num_of_effective_jumps"][ctypes.c_ulong(1)].value
print("Func %s has been called %s times!" % (func_name, called))
called = b["num_of_calling"][ctypes.c_ulong(1)].value
print("Func end %s has been called %s times!" % (func_name, called))
called = b["num_of_returning"][ctypes.c_ulong(1)].value
print("Func end %s has been returned %s times!" % (func_name, called))

for k, v in sorted(b.get_table("return_values").items(), key=lambda kv: kv[0].value):
    print(f"key: {k.value:016x}, value: {v.value:}")

for reg in regs:
  table_name = "hash_%s" % (reg)
  print("num_of_effective_jumps for %s:" % (table_name))
  table = b.get_table(table_name)
  count = sum([v.value for _, v in table.items()])
  print("count: ", count)
  possibly_double_freed = [k for k, v in table.items() if v.value > 1 and k.value != 0]
  for k, v in sorted(table.items(), key=lambda kv: kv[0].value):
      if v.value > 1 and k.value != 0:
          print(f"key: {k.value:016x}, value: {v.value:}")
  table_name = "hash_mem_%s" % (reg)
  print("num_of_effective_jumps for %s:" % (table_name))
  table = b.get_table(table_name)
  for k in possibly_double_freed:
      print(k, table[k])
