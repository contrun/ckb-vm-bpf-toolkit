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
