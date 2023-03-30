#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.join(
  os.path.dirname(os.path.abspath(__file__)), "..", "contrib"))

from debugger import build_debugger_process
from bcc import BPF, USDT
import ctypes

bpf_text = """
BPF_HASH(stats, uint64_t);

int do_execute(struct pt_regs *ctx) {
    stats.increment(1);

    return 0;
}
"""

p = build_debugger_process()

u = USDT(pid=int(p.pid))
u.enable_probe(probe="ckb_vm:execute_inst", fn_name="do_execute")
b = BPF(text=bpf_text, usdt_contexts=[u], cflags=["-Wno-macro-redefined"])

p.communicate(input="\n".encode())
print()
print()

executed_insts = b["stats"][ctypes.c_ulong(1)].value
print("Executed instructions:", executed_insts)
