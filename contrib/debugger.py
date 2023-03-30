import os
import shutil
from subprocess import Popen, PIPE
import sys

def build_debugger_process():
  ckb_debugger_path = os.environ.get("CKB_DEBUGGER") or shutil.which("ckb-debugger")
  if ckb_debugger_path is None:
    print("Please use CKB_DEBUGGER environment variable, or make sure ckb-debugger is in PATH", file=sys.stderr)
    exit(1)
  ckb_debugger_path = os.path.abspath(ckb_debugger_path)

  for arg in sys.argv:
    if arg == "--mode":
      print("bpf tools do not allow switching debugger mode!", file=sys.stderr)
      exit(1)

  popen_args = [ckb_debugger_path, "--mode", "probe", "--prompt"]
  popen_args.extend(sys.argv[1:])

  return Popen(popen_args, stdin=PIPE)

def locate_bin():
  for a, b in zip(sys.argv, sys.argv[1:]):
    if a == "--bin":
      return b
  print("A binary must be provided for inspection!", file=sys.stderr)
  exit(1)

def extract_bpf_arg(key):
  key = "--bpf-%s" % ( key )
  for i in range(len(sys.argv) - 1):
    if sys.argv[i] == key:
      val = sys.argv[i + 1]
      del sys.argv[i:i + 2]
      return val
  print("Cannot locate key %s in argv!" %( key ), file=sys.stderr)
  exit(1)
