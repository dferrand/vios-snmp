"""ssh/scp to a VIOS, in the same shape as tools/vios_ifix.py's Vios class.

Deliberately small and dependency-free: this repo has to be usable on its own
(the efix tools cannot be imported from here), but the semantics are identical
so the two can be merged later without rewriting either.

Two things the padmin shell forces:

* commands that exist as VIOS aliases only exist inside `ioscli`, which is what
  run() prefixes;
* /etc is not writable from the padmin shell, so anything that touches a file
  goes through `oem_setup_env` (root) and its stdin, not its argv. The root
  shell prints a banner before running anything, so output that must be parsed
  is bracketed with sentinels rather than trusted wholesale.
"""

import os
import re
import shlex
import subprocess

RC = re.compile(r"^__VS_RC__=(\d+)\s*$", re.M)
RC_ANY = re.compile(r"^__VS_RC__=.*$", re.M)


class Abort(Exception):
    def __init__(self, msg, code=1):
        Exception.__init__(self, msg)
        self.msg, self.code = msg, code


def _run(argv, input=None, timeout=None):
    """subprocess.run with text output; written for Python 3.6 (no capture_output / text=)."""
    kw = {"stdout": subprocess.PIPE, "stderr": subprocess.PIPE, "universal_newlines": True, "timeout": timeout}
    if input is None:
        kw["stdin"] = subprocess.DEVNULL  # 3.6 refuses stdin= together with input=
    else:
        kw["input"] = input
    return subprocess.run(argv, **kw)


class Vios(object):
    """ssh/scp to a VIOS as padmin, with a root() path through oem_setup_env."""

    def __init__(self, host, user="padmin", ssh_opts=()):
        self.host, self.user = host, user
        self.opts = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=15"] + list(ssh_opts)

    @property
    def target(self):
        return "%s@%s" % (self.user, self.host)

    def run(self, cmd, timeout=None, answer=None):
        """A command in the padmin shell (ioslevel, lssrc, startsrc ...) -> (rc, output)."""
        if not cmd.startswith("ioscli "):
            cmd = "ioscli " + cmd
        p = _run(["ssh", "-T"] + self.opts + [self.target, cmd], input=answer, timeout=timeout)
        return p.returncode, p.stdout + p.stderr

    def root(self, cmd, timeout=None):
        """A script in the root shell, through oem_setup_env -> (rc, output).

        `cmd` may be several lines: it is piped to the root shell's stdin.
        """
        script = "(\n%s\n) 2>&1\necho \"__VS_RC__=$?\"\nexit\n" % cmd
        p = _run(["ssh", "-T"] + self.opts + [self.target, "ioscli oem_setup_env"], input=script, timeout=timeout)
        m = RC.search(p.stdout)
        if p.returncode != 0 and not m:
            return p.returncode, p.stdout + p.stderr
        out = RC_ANY.sub("", p.stdout).strip("\n") if m else p.stdout
        return (int(m.group(1)) if m else 1), out

    def root_read(self, path):
        """Contents of a root-only file, delimited so the root shell's banner is not mistaken for data."""
        rc, out = self.root("echo __VS_BEGIN__\ncat %s\necho __VS_END__" % shlex.quote(path))
        m = re.search(r"^__VS_BEGIN__\s*$(.*)^__VS_END__\s*$", out, re.S | re.M)
        if not m:
            raise Abort("cannot read %s on %s: %s" % (path, self.host, out.strip()[-400:]))
        return m.group(1).lstrip("\n")

    def put(self, local, remote_dir):
        p = _run(["scp", "-q"] + self.opts + [local, "%s:%s/" % (self.target, remote_dir)])
        if p.returncode:
            raise Abort("scp %s failed: %s" % (os.path.basename(local), p.stderr.strip()))


def level(vios):
    rc, out = vios.run("ioslevel", timeout=60)
    return out.strip().split("\n")[-1].strip() if rc == 0 else "unknown"
