"""vios_snmp.py end to end against a fake VIOS: plan, apply, restart, verify, roll back."""
import contextlib
import io
import os
import re
import sys
import unittest
import unittest.mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, HERE)

import vios_snmp as T                     # noqa: E402
import vioslib.snmpconf as S              # noqa: E402
from vioslib import vios as V             # noqa: E402

FIX = os.path.join(HERE, "fixtures")


def fixture(name):
    with open(os.path.join(FIX, name)) as f:
        return f.read()


ORIG = fixture("snmpdv3.conf.orig")
ADJUSTED = fixture("snmpdv3.conf.adjusted")
RC = fixture("rc.tcpip.orig")

COMMUNITY = "CHANGEME"


def without_traps(text):
    return [t for t in S.active(text) if t[0] not in S.TRAP_DIRECTIVES]


class FakeVios(object):
    """Answers the four scripts vios_snmp.py sends, and keeps the files in memory."""

    def __init__(self, conf=ORIG, rc=RC, verify_ok=True):
        self.host = "vios1"
        self.files = {S.CONF: conf, S.RC_TCPIP: rc}
        self.services = {s: "inoperative" for s in S.SUBSYSTEMS}
        self.verify_ok = verify_ok
        self.puts = {}
        self.calls = []

    # -- the four entry points the tool uses ------------------------------
    def run(self, cmd, timeout=None, answer=None):
        if "ioslevel" in cmd:
            return 0, "3.1.4.20\n"
        return 0, ""

    def put(self, local, remote_dir):
        with open(local) as f:
            self.puts[os.path.basename(local)] = f.read()

    def root_read(self, path):
        return self.files[path]

    def root(self, cmd, timeout=None):
        self.calls.append(cmd)
        if "__VS_AGENT__" in cmd:
            return 0, self._probe()
        if "__VS_T_" in cmd:
            return 0, self._verify(cmd)
        if cmd.startswith("mkdir -p"):
            return 0, ""
        if cmd.startswith("cp /home/padmin"):
            return 0, self._install(cmd)
        if cmd.startswith("cp -p") and "snmpdv3.conf.bak " in cmd:
            return 0, self._restore()
        if "stopsrc" in cmd:
            for s in self.services:
                self.services[s] = "inoperative"
            return 0, ""
        if "startsrc" in cmd:
            for s in S.SUBSYSTEMS:
                if "startsrc -s %s" % s in cmd:
                    self.services[s] = "active"
            return 0, ""
        return 0, ""

    # -- far-side behaviour ----------------------------------------------
    def _probe(self):
        out = ["__VS_AGENT__", "lrwxrwxrwx 1 root system 9 Nov  9 2015 /usr/sbin/snmpd -> /usr/sbin/snmpdv3ne",
               "__VS_BOOTUP__", "no"]
        for s in S.SUBSYSTEMS:
            out += ["__VS_SVC__" + s, " %s        tcpip      %-8s %s" % (s, 1234, self.services[s])]
        return "\n".join(out + ["__VS_CONF__", self.files[S.CONF].rstrip("\n"),
                                "__VS_RC__", self.files[S.RC_TCPIP].rstrip("\n"), "__VS_END__", ""])

    def _install(self, cmd):
        for name, dest in re.findall(r"cp /home/padmin/([^\s;]+) ([^\s;]+)", cmd):
            if name not in self.puts:
                return "cp: %s: No such file" % name
            self.files[dest] = self.puts[name]
        return ""

    def _restore(self):
        self.files[S.CONF] = ORIG
        self.files[S.RC_TCPIP] = RC
        return ""

    def _verify(self, cmd):
        body = {"system": 'sysDescr.0 = "IBM PowerPC CHRP Computer"',
                "aixmibd": "aixPageThreshold.0 = 95",
                "hostmibd": "1.3.6.1.2.1.25.1.1.0 = 1234567"}
        out = []
        for key in ("system", "aixmibd", "hostmibd"):
            if "__VS_T_%s__" % key not in cmd:
                continue
            out += ["__VS_T_%s__" % key,
                    body[key] if self.verify_ok else "snmpinfo: 0821-103 No response.",
                    "__VS_T_%s_rc__=%d" % (key, 0 if self.verify_ok else 1)]
        return "\n".join(out + [""])


def run(args, fake):
    """Run main() with the fake in place; return (rc, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        with unittest.mock.patch.object(V, "Vios", lambda *a, **k: fake):
            rc = T.main(["--host", "vios1"] + args)
    return rc, out.getvalue(), err.getvalue()


class PlanTest(unittest.TestCase):
    def test_plan_reports_drift_without_touching_anything(self):
        fake = FakeVios()
        rc, out, _ = run(["--community", COMMUNITY], fake)
        self.assertEqual(rc, 10)
        self.assertEqual(fake.files[S.CONF], ORIG)
        self.assertFalse([c for c in fake.calls if c.startswith("cp ")])
        self.assertIn("COMMUNITY %s" % COMMUNITY, out)
        self.assertIn("plan: 5 change(s)", out)

    def test_plan_lists_the_findings(self):
        rc, out, _ = run(["--community", COMMUNITY], FakeVios())
        self.assertIn("3 trap directive(s) left untouched", out)
        self.assertIn("TARGET_PARAMETERS still names community public", out)

    def test_recon_needs_no_community(self):
        fake = FakeVios()
        rc, out, _ = run([], fake)
        self.assertEqual(rc, 0)
        self.assertIn("snmpdv3ne", out)
        self.assertIn("recon only", out)
        self.assertFalse([c for c in fake.calls if "cp " in c])

    def test_manager_acl_reaches_the_file(self):
        rc, _, _ = run(["--community", "c", "--manager", "10.20.0.10", "--print-config"], FakeVios())
        self.assertEqual(rc, 10)

    def test_json_plan_is_parseable(self):
        import json
        rc, out, _ = run(["--community", COMMUNITY, "--json"], FakeVios())
        report = json.loads(out)
        self.assertEqual(rc, 10)
        self.assertEqual(report["host"], "vios1")
        self.assertEqual(len(report["changes"]), 9)          # 5 in snmpdv3.conf + 4 in rc.tcpip


class ApplyTest(unittest.TestCase):
    def test_apply_writes_restarts_and_verifies(self):
        fake = FakeVios()
        rc, out, err = run(["--community", COMMUNITY, "--apply"], fake)
        self.assertEqual(rc, 0, err)
        self.assertIn("backed up to /home/padmin/.vios_snmp-", out)
        self.assertEqual(without_traps(fake.files[S.CONF]), without_traps(ADJUSTED))
        self.assertEqual(S.rc_autostart(fake.files[S.RC_TCPIP]), {s: True for s in S.SUBSYSTEMS})
        self.assertEqual(fake.services, {s: "active" for s in S.SUBSYSTEMS})
        self.assertIn("ok   system", out)

    def test_subagents_are_started_with_the_community(self):
        fake = FakeVios()
        run(["--community", COMMUNITY, "--apply"], fake)
        starts = [c for c in fake.calls if "startsrc" in c]
        self.assertTrue(starts)
        self.assertIn('startsrc -s aixmibd -a "-c %s"' % COMMUNITY, starts[-1])

    def test_subagents_stop_before_the_agent(self):
        fake = FakeVios()
        run(["--community", COMMUNITY, "--apply"], fake)
        stop = [c for c in fake.calls if "stopsrc" in c and "\n" in c][0]
        # the subagents go down in one loop, and that loop precedes `stopsrc -s snmpd`
        self.assertLess(stop.index("for s in snmpmibd hostmibd aixmibd"),
                        stop.index("stopsrc -s snmpd"))

    def test_second_apply_is_a_no_op(self):
        fake = FakeVios()
        run(["--community", COMMUNITY, "--apply"], fake)
        fake.calls = []
        rc, out, _ = run(["--community", COMMUNITY, "--apply"], fake)
        self.assertEqual(rc, 0)
        self.assertIn("configuration already matches the plan", out)
        self.assertFalse([c for c in fake.calls if "stopsrc" in c or c.startswith("cp /home/padmin")])

    def test_apply_with_no_traps(self):
        fake = FakeVios()
        rc, _, _ = run(["--community", COMMUNITY, "--apply", "--no-traps"], fake)
        self.assertEqual(rc, 0)
        self.assertEqual(S.trap_entries(fake.files[S.CONF]), [])

    def test_no_restart_skips_the_daemons(self):
        fake = FakeVios()
        rc, _, _ = run(["--community", COMMUNITY, "--apply", "--no-restart"], fake)
        self.assertEqual(rc, 0)
        self.assertEqual(fake.services, {s: "inoperative" for s in S.SUBSYSTEMS})


class VerifyTest(unittest.TestCase):
    def test_failed_check_rolls_the_files_back(self):
        fake = FakeVios(verify_ok=False)
        rc, out, err = run(["--community", COMMUNITY, "--apply"], fake)
        self.assertEqual(rc, 1)
        self.assertEqual(fake.files[S.CONF], ORIG)
        self.assertEqual(fake.files[S.RC_TCPIP], RC)
        self.assertIn("rolling back", err)
        self.assertIn("FAIL system", out)

    def test_apply_requires_a_community(self):
        fake = FakeVios()
        with self.assertRaises(SystemExit):
            run(["--apply"], fake)
        self.assertEqual(fake.files[S.CONF], ORIG)


if __name__ == "__main__":
    unittest.main()
