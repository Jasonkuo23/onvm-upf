#!/usr/bin/env python3
"""Compile the actual UPF-C worker with timer library; no ONVM runtime needed."""
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[3]
build = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else root / 'build'
entries = json.loads((build / 'compile_commands.json').read_text())
entry = next(e for e in entries if e['file'].endswith('/upf_c/upf_init.c'))
args = shlex.split(entry['command'])
compiler = args.pop(0)
flags = []
while args:
    arg = args.pop(0)
    if arg in ('-o', '-MF', '-MQ', '-MT'):
        args.pop(0)
    elif arg not in ('-MD', '-MMD', '-c', entry['file']):
        flags.append(arg)
flags += ['-ffunction-sections', '-fdata-sections', '-UNDEBUG']
# Use section GC to exclude UPF startup code; test supplies Self/ThreadStop/logging.
sources = [root / '5gc/upf_c/upf_init.c', root / 'onvm/utlt/utlt_timer.c',
           root / 'onvm/utlt/utlt_time.c', Path(__file__).with_name('timer_thread_test.c')]
with tempfile.TemporaryDirectory(prefix='upfc-timer-test-') as scratch:
    objects = []
    for i, source in enumerate(sources):
        obj = Path(scratch) / f'{i}.o'
        subprocess.run([compiler, *flags, '-c', str(source), '-o', str(obj)],
                       cwd=entry['directory'], check=True)
        objects.append(str(obj))
    exe = str(Path(scratch) / 'timer-test')
    subprocess.run([compiler, *objects, '-pthread', '-Wl,--gc-sections',
                    '-Wl,--wrap=nanosleep', '-o', exe], check=True)
    subprocess.run([exe], check=True, timeout=10)
