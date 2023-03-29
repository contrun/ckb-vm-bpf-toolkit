#!/usr/bin/env python3

from bcc import BPF, USDT
import argparse
import ctypes
import os
import shutil
from subprocess import Popen, PIPE
import sys

parser = argparse.ArgumentParser(
  prog='functrace',
  description='ckb-vm-bpf-toolkit funcs')
parser.add_argument("--ckb-debugger")
parser.add_argument("--tx-file", required=True)
parser.add_argument("--cell-type", required=True, choices=["input", "output"])
parser.add_argument("--script-group-type", required=True, choices=["lock", "type"])
parser.add_argument("--cell-index", required=True)
args = parser.parse_args()

ckb_debugger_path = args.ckb_debugger or os.environ.get("CKB_DEBUGGER") or shutil.which("ckb-debugger")
if ckb_debugger_path is None:
  print("Please use CKB_DEBUGGER environment variable, or make sure ckb-debugger is in PATH", file=sys.stderr)
  exit(1)
ckb_debugger_path = os.path.abspath(ckb_debugger_path)

bpf_text = """
BPF_HASH(stats, uint64_t);

int do_execute(struct pt_regs *ctx) {
    stats.increment(1);

    return 0;
}
"""

p = Popen([
  ckb_debugger_path,
  "--tx-file", args.tx_file,
  "--cell-type", args.cell_type,
  "--script-group-type", args.script_group_type,
  "--cell-index", args.cell_index,
  "--mode", "probe",
  "--prompt"
], stdin=PIPE)

u = USDT(pid=int(p.pid))
u.enable_probe(probe="ckb_vm:execute_inst", fn_name="do_execute")
b = BPF(text=bpf_text, usdt_contexts=[u], cflags=["-Wno-macro-redefined"])

p.communicate(input="\n".encode())
print()
print()

executed_insts = b["stats"][ctypes.c_ulong(1)].value
print("Executed instructions:", executed_insts)
