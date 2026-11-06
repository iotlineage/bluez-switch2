#!/usr/bin/env python3
"""Run fake transports on a private bus; requires mapped root, never host root."""
import os
import subprocess
import sys
import tempfile
from pathlib import Path
binary=str(Path(sys.argv[1]).resolve())
def run(mode,store,code=0):
    env=os.environ.copy()
    if mode: env['S2_FIXTURE_MODE']=mode
    else: env.pop('S2_FIXTURE_MODE',None)
    p=subprocess.run([binary,str(store)],env=env,timeout=10)
    assert p.returncode==code,(mode,p.returncode,code)
for mode in ('','cancel-before','cancel-during-intent','cancel-after-commit','storage-failure-intent',
             'bad-peer','bad-challenge','bad-ack','slow-storage','remove-during-intent','capability-missing','ack-lost','storage-failure-ack','activation-failure',
             'crash-intent','crash-commit','crash-ack'):
    with tempfile.TemporaryDirectory() as tmp:
        run(mode,tmp,91 if mode=='crash-commit' else 90 if mode.startswith('crash-') else 0)
        if mode in ('activation-failure','crash-ack'): run('recover',tmp)
        if mode in ('ack-lost','storage-failure-ack','crash-intent','crash-commit'): run('recover-uncertain',tmp)
for kind in ('bad-version','wrong-peer','duplicate-key','insecure-mode','symlink','truncated'):
    with tempfile.TemporaryDirectory() as tmp:
        directory=Path(tmp)/'adapter/06:05:04:03:02:01';directory.mkdir(parents=True,mode=0o700)
        path=directory/'switch2-association'
        text='[Association]\nVersion=1\nAdapter=A6:A5:A4:A3:A2:A1\nPeer=06:05:04:03:02:01\nState=acknowledged\nKeyLE='+'23'*16+'\n'
        if kind=='bad-version':text=text.replace('Version=1','Version=99')
        if kind=='wrong-peer':text=text.replace('Peer=06','Peer=16')
        if kind=='duplicate-key':text+='KeyLE='+'24'*16+'\n'
        if kind=='truncated':text=text[:-5]
        path.write_text(text);path.chmod(0o644 if kind=='insecure-mode' else 0o600)
        if kind=='symlink':
            path.rename(directory/'secret');path.symlink_to('secret')
        run('malformed',tmp)
print('PASS: live state, crash recovery, storage validation and responsiveness suite')
