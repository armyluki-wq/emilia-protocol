#!/usr/bin/env python3
"""Check bounded two-run observation equivalence and the safety/availability fork."""
import hashlib
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
JAR = pathlib.Path(sys.argv[1]).expanduser() if len(sys.argv) > 1 else pathlib.Path.home() / '.cache/emilia/formal/tla2tools-1.7.4.jar'
assert hashlib.sha256(JAR.read_bytes()).hexdigest() == '936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88'
for policy in ['safe', 'all', 'unsafe']:
    with tempfile.TemporaryDirectory(prefix='ep906-twoworld-') as scratch:
        result = subprocess.run(['java', '-Xmx512m', '-XX:+UseParallelGC', '-cp', str(JAR),
            'tlc2.TLC', '-workers', '1', '-metadir', scratch,
            '-config', f'formal/ep_replay_history_twoworld_{policy}.cfg',
            'formal/ep_replay_history_twoworld.tla'], cwd=ROOT, text=True,
            capture_output=True, timeout=60)
        output = result.stdout + result.stderr
        (ROOT / f'formal/ep_replay_history_results/twoworld-{policy}.log').write_text(output)
        if policy == 'unsafe':
            assert result.returncode == 12 and 'Invariant ReplaySafe is violated' in output, output
            assert '<Compare ' in output and '<Decide ' in output, output
            assert output.count('<Crash ') == 2, output
            assert '<ConsumeH1 ' in output and '<EnterH1 ' in output, output
            assert 'actualCalls |-> 2' in output and 'recoveryCalls |-> 1' in output, output
        else:
            assert result.returncode == 0, output
            assert 'Model checking completed. No error has been found.' in output, output
            assert 'Finished checking temporal properties' in output, output
        counts = re.search(r'(\d+ states generated, \d+ distinct states found)', output)
        assert counts, output
        print(f'{policy}: {"expected ReplaySafe counterexample" if policy == "unsafe" else "PASS"}; {counts[1]}')
