#!/usr/bin/env python3
"""Bounded TLC reproduction; no downloads, installs, shared evidence regeneration."""
import hashlib
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
JAR = pathlib.Path(sys.argv[1]).expanduser() if len(sys.argv) > 1 else pathlib.Path.home() / '.cache/emilia/formal/tla2tools-1.7.4.jar'
EXPECTED = '936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88'
if hashlib.sha256(JAR.read_bytes()).hexdigest() != EXPECTED:
    raise SystemExit('Pinned TLC JAR hash mismatch')
for mode, mutation in [('safe', None), ('missing', 'UnsafeTreatMissingHistoryAsUnused'),
                       ('rollback', 'UnsafeAllowRolledBackAnchor'),
                       ('common', 'CommonSnapshotRestore'), ('live', None), ('recovery', None), ('uncovered', None), ('compaction', None)]:
    with tempfile.TemporaryDirectory(prefix=f'ep906-{mode}-') as scratch:
        result = subprocess.run(['java', '-Xmx512m', '-XX:+UseParallelGC', '-cp', str(JAR),
            'tlc2.TLC', '-workers', '1', '-metadir', scratch,
            '-config', f'formal/ep_replay_history_{mode}.cfg',
            'formal/ep_replay_history.tla'], cwd=ROOT, text=True,
            capture_output=True, timeout=60)
        output = result.stdout + result.stderr
        (ROOT / f'formal/ep_replay_history_results/{mode}.log').write_text(output)
        if mutation:
            assert result.returncode == 12, (mode, result.returncode, output)
            assert 'Invariant AtMostOnce is violated' in output, (mode, output)
            assert f'<{mutation} ' in output, (mode, output)
            assert output.count('<ConsumeLinearized ') == 2, (mode, output)
            assert output.count('<ProviderEntry ') == 2, (mode, output)
            if mode in {'rollback', 'common'}:
                assert '<CheckpointAnchored ' in output, (mode, output)
        else:
            assert result.returncode == 0, (mode, result.returncode, output)
            assert 'Model checking completed. No error has been found.' in output
            if mode in {'live', 'recovery', 'uncovered', 'compaction'}:
                assert 'Finished checking temporal properties' in output
        counts = re.search(r'(\d+ states generated, \d+ distinct states found)', output)
        assert counts, (mode, output)
        print(f'{mode}: {"expected AtMostOnce counterexample" if mutation else "PASS"}; {counts[1]}')
