#!/usr/bin/env python3
"""Actual renameat2/usermod/groupmod on disposable CI only. /tmp fixtures only."""
import grp
import os
from pathlib import Path
import pwd
import sqlite3
import subprocess
import tempfile

from fixtures import FixtureOps,host
from probe_tls_residue import TlsBlocked


def command(argv):
    subprocess.run(argv,check=True,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20)


def main():
    if not (os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true' and
            os.environ.get('STUDIO_QUARANTINE_CI')=='1' and os.environ.get('RUNNER_TEMP') and
            not Path('/opt/studio1925').exists()):raise SystemExit('DISPOSABLE_CI_REQUIRED')
    for name in (host.TLS_USER,host.HOLD):
        for get in (pwd.getpwnam,grp.getgrnam):
            try:get(name)
            except KeyError:continue
            raise SystemExit('CI_IDENTITY_COLLISION')
    root_before=pwd.getpwnam('root')
    created=False
    try:
        command(['/usr/sbin/useradd','--system','--user-group','--home-dir','/nonexistent','--no-create-home','--shell','/usr/sbin/nologin',host.TLS_USER]);created=True
        identity=pwd.getpwnam(host.TLS_USER)
        with tempfile.TemporaryDirectory(prefix='studio-quarantine-ci-') as tmp:
            ops=FixtureOps(Path(tmp),real_identity=True);before=ops.baseline()
            # Dedicated synthetic SQLite only, never the application's DB.
            ops.canary.unlink()
            with sqlite3.connect(ops.canary) as db:
                db.execute('CREATE TABLE canary(value TEXT NOT NULL)');db.execute("INSERT INTO canary VALUES ('synthetic fixture')")
            db.close()
            before=ops.baseline()
            result=host.quarantine_once('check','',ops);assert result['status']=='READY',result
            result=host.quarantine_once('quarantine',host.CONFIRM,ops);assert result['status']=='SUCCESS',result
            held=pwd.getpwnam(host.HOLD)
            assert (held.pw_uid,held.pw_gid,held.pw_dir,held.pw_shell)==(identity.pw_uid,identity.pw_gid,identity.pw_dir,identity.pw_shell)
            assert grp.getgrnam(host.HOLD).gr_gid==identity.pw_gid
            assert ops.baseline()==before and pwd.getpwnam('root')==root_before
            with sqlite3.connect('file:'+str(ops.canary)+'?mode=ro',uri=True) as db:
                assert db.execute('SELECT value FROM canary').fetchall()==[('synthetic fixture',)]
            db.close()
            foreign=Path(tmp)/'foreign-uid-reference';foreign.touch();os.chown(foreign,identity.pw_uid,identity.pw_gid)
            try:ops.dependencies(ops.user)
            except TlsBlocked as error:assert str(error)=='DEPENDENCY_FOUND'
            else:raise AssertionError('Foreign UID reference was ignored')
            foreign.unlink()  # disposable fixture only
            assert host.quarantine_once('quarantine',host.CONFIRM,ops)['status']=='BLOCKED'
            # Prove reversibility of the standard account rename, not an app rollback.
            command(['/usr/sbin/groupmod','--new-name',host.TLS_USER,host.HOLD])
            command(['/usr/sbin/usermod','--login',host.TLS_USER,host.HOLD])
            restored=pwd.getpwnam(host.TLS_USER)
            assert (restored.pw_uid,restored.pw_gid)==(identity.pw_uid,identity.pw_gid)
            for source,target in reversed(tuple(zip(host.TLS_ROOTS,host.TARGETS))):ops.move(target,source)
            assert ops.prove().report['status']=='MATCHED_FAILED_PREPARE'
            assert pwd.getpwnam('root')==root_before
        print('REAL_ONE_TIME_QUARANTINE_OK: native atomic moves, UID/GID reservation, reversible identity, no-clobber, canary preserved')
    finally:
        # CI-created identities only, never code embedded in a VPS payload.
        if created:
            for name in (host.TLS_USER,host.HOLD):
                try:pwd.getpwnam(name)
                except KeyError:continue
                command(['/usr/sbin/userdel',name])
            for name in (host.TLS_USER,host.HOLD):
                try:grp.getgrnam(name)
                except KeyError:continue
                command(['/usr/sbin/groupdel',name])


if __name__=='__main__':main()
