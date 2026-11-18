"""vios_snmp.py end to end against a fake VIOS: plan, apply, restart, verify, roll back.

The fake also models the SRC subsystem object: `odmget` returns the stanza and
`lssrc -Ss` the colon-separated row, and `ps -ef` shows what the running
subagents were started with, so every half of the cmdargs check is exercised.
"""
import contextlib
import io
import json
import os
import re
import shlex
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
SUBCMD = "-c " + COMMUNITY


def without_traps(text):
    return [t for t in S.active(text) if t[0] not in S.TRAP_DIRECTIVES]


def configured():
    """The two files as the tool would leave them: a host that only lacks the ODM part."""
    return S.conf_desired(ORIG, community=COMMUNITY)[0], S.rc_desired(RC)[0]


def healthy(**kw):
    """A VIOS that is fully configured and answering: the baseline for the --test mode."""
    conf, rc_text = configured()
    kw.setdefault("cmdargs", {s: SUBCMD for s in S.SUBAGENTS})
    fake = FakeVios(conf=conf, rc=rc_text, **kw)
    fake.services = {s: "active" for s in S.SUBSYSTEMS}
    return fake


class FakeVios(object):
    """Answers the scripts vios_snmp.py sends, and keeps the files and the ODM in memory."""

    def __init__(self, conf=ORIG, rc=RC, verify_ok=True, cmdargs=None,
                 chssys_sticks=True, ps_hides=False, bodies=None,
                 odm_absent=False, lssrc_cmdargs=None):
        self.host = "vios1"
        self.files = {S.CONF: conf, S.RC_TCPIP: rc}
        self.services = {s: "inoperative" for s in S.SUBSYSTEMS}
        self.cmdargs = dict(cmdargs if cmdargs is not None
                            else {s: "" for s in S.SUBAGENTS})
        self.verify_ok = verify_ok
        self.chssys_sticks = chssys_sticks     # False: chssys exits 0 but nothing is stored
        self.ps_hides = ps_hides               # True: processes run without their -c
        self.bodies = dict(bodies or {})       # {check: (snmpinfo output, rc)} overrides
        self.odm_absent = odm_absent           # True: odmget returns nothing (lssrc fallback)
        self.lssrc_cmdargs = lssrc_cmdargs     # what lssrc -Ss claims, when it disagrees
        self.puts = {}
        self.calls = []

    # -- the entry points the tool uses -----------------------------------
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
        if "chssys" in cmd:
            return 0, self._chssys(cmd)
        if "__VS_CMD__" in cmd:
            return 0, self._cmdargs(cmd)
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
    def _src_row(self, sub):
        args = self.cmdargs.get(sub, "")
        if self.lssrc_cmdargs is not None:
            args = self.lssrc_cmdargs.get(sub, "")
        return "%s::%s:/usr/sbin/%s:0:0:/dev/console:/dev/console:/dev/console:" % (sub, args, sub)

    def _odm(self, sub):
        """The SRCsubsys stanza exactly as odmget prints it."""
        if self.odm_absent:
            return ""
        return ("SRCsubsys:\n"
                '\tsubsysname = "%s"\n'
                '\tsynonym = ""\n'
                '\tcmdargs = "%s"\n'
                '\tpath = "/usr/sbin/%s"\n'
                '\tuid = "0"\n'
                '\tauditid = "0"\n'
                '\tstandin = "/dev/console"\n'
                '\tstandout = "/dev/console"\n'
                '\tstanderr = "/dev/console"\n'
                '\taction = "-O"\n'
                '\tmulti = "-Q"\n'
                '\tcontact = "-K"\n'
                '\tsvrkey = "0"\n'
                '\tsvrmtype = "0"\n'
                '\tpriority = "20"\n'
                '\tsignorm = "0"\n'
                '\tsigforce = "0"\n'
                '\tdisplay = "-d"\n'
                '\twaittime = "20"\n'
                '\tgrpname = "tcpip"\n') % (sub, self.cmdargs.get(sub, ""), sub)

    def _probe(self):
        out = ["__VS_AGENT__", "lrwxrwxrwx 1 root system 9 Nov  9 2015 /usr/sbin/snmpd -> /usr/sbin/snmpdv3ne",
               "__VS_BOOTUP__", "no"]
        for s in S.SUBSYSTEMS:
            out += ["__VS_SVC__" + s, " %s        tcpip      %-8s %s" % (s, 1234, self.services[s])]
        for s in S.SUBAGENTS:
            out += ["__VS_CMD__" + s, self._odm(s), "__VS_LSSRC__" + s, self._src_row(s)]
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

    def _chssys(self, cmd):
        for line in cmd.splitlines():
            if not line.strip().startswith("chssys"):
                continue
            parts = shlex.split(line)
            sub = parts[parts.index("-s") + 1]
            args = parts[parts.index("-a") + 1] if "-a" in parts else ""
            if self.chssys_sticks:
                self.cmdargs[sub] = args
        return ""

    def _cmdargs(self, cmd):
        out = []
        if "__VS_PS__" in cmd:
            out.append("__VS_PS__")
            for s in S.SUBAGENTS:
                if self.services.get(s) != "active":
                    continue
                arg = "" if self.ps_hides else self.cmdargs.get(s, "")
                out.append("    root  1234     1   0 10:00:00      -  0:00 /usr/sbin/%s%s"
                           % (s, (" " + arg) if arg else ""))
        for s in S.SUBAGENTS:
            if "__VS_CMD__" + s in cmd:
                out += ["__VS_CMD__" + s, self._odm(s)]
            if "__VS_LSSRC__" + s in cmd:
                out += ["__VS_LSSRC__" + s, self._src_row(s)]
        return "\n".join(out + [""])

    def _verify(self, cmd):
        """snmpinfo answers with text shaped like the real thing: fixtures, not inline strings."""
        out = []
        for key in ("system", "aixmibd", "hostmibd"):
            if "__VS_T_%s__" % key not in cmd:
                continue
            if key in self.bodies:
                body, rc = self.bodies[key]
            elif self.verify_ok:
                body, rc = fixture("snmpinfo.%s.txt" % key), 0
            else:
                body, rc = fixture("snmpinfo.noresponse.txt"), 1
            out += ["__VS_T_%s__" % key, body.rstrip("\n"), "__VS_T_%s_rc__=%d" % (key, rc)]
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

    def test_plan_shows_the_chssys_commands_and_touches_no_odm(self):
        fake = FakeVios()
        rc, out, _ = run(["--community", COMMUNITY], fake)
        self.assertEqual(rc, 10)
        self.assertIn("SRC cmdargs  (3 changes)", out)
        for sub in S.SUBAGENTS:
            self.assertIn("chssys -s %s -a '-c %s'" % (sub, COMMUNITY), out)
        self.assertEqual(fake.cmdargs, {s: "" for s in S.SUBAGENTS})
        self.assertFalse([c for c in fake.calls if "chssys" in c])

    def test_plan_lists_the_findings(self):
        rc, out, _ = run(["--community", COMMUNITY], FakeVios())
        self.assertIn("3 trap directive(s) left untouched", out)
        self.assertIn("TARGET_PARAMETERS still names community public", out)

    def test_recon_needs_no_community(self):
        fake = FakeVios()
        rc, out, _ = run([], fake)
        self.assertEqual(rc, 0)
        self.assertIn("snmpdv3ne", out)
        self.assertIn("mibd args", out)
        self.assertIn("recon only", out)
        self.assertFalse([c for c in fake.calls if "cp " in c])

    def test_recon_shows_the_community_already_in_the_odm(self):
        fake = FakeVios(cmdargs={s: "-c oldcomm" for s in S.SUBAGENTS})
        rc, out, _ = run([], fake)
        self.assertEqual(rc, 0)
        self.assertIn("aixmibd -c oldcomm", out)

    def test_manager_acl_reaches_the_file(self):
        rc, _, _ = run(["--community", "c", "--manager", "10.20.0.10", "--print-config"], FakeVios())
        self.assertEqual(rc, 10)

    def test_the_boot_script_carries_no_community(self):
        rc, out, _ = run(["--community", COMMUNITY, "--print-config"], FakeVios())
        self.assertEqual(rc, 10)
        rc_part = out.split("--- %s ---" % S.RC_TCPIP, 1)[1]
        self.assertNotIn(COMMUNITY, rc_part)
        self.assertIn('start /usr/sbin/aixmibd "$src_running"\n', rc_part)

    def test_json_plan_is_parseable(self):
        rc, out, _ = run(["--community", COMMUNITY, "--json"], FakeVios())
        report = json.loads(out)
        self.assertEqual(rc, 10)
        self.assertEqual(report["host"], "vios1")
        self.assertEqual(len(report["changes"]), 9)          # 5 in snmpdv3.conf + 4 in rc.tcpip
        self.assertEqual(len(report["cmdargs_changes"]), 3)
        self.assertEqual(report["cmdargs_changes"][0]["command"],
                         "chssys -s aixmibd -a '-c %s'" % COMMUNITY)

    def test_a_host_that_only_lacks_the_odm_part(self):
        conf, rc_text = configured()
        fake = FakeVios(conf=conf, rc=rc_text)
        rc, out, _ = run(["--community", COMMUNITY, "--json"], fake)
        report = json.loads(out)
        self.assertEqual(rc, 10)
        self.assertEqual(report["changes"], [])
        self.assertEqual([c["subsystem"] for c in report["cmdargs_changes"]],
                         ["aixmibd", "hostmibd", "snmpmibd"])


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
        self.assertIn("ok   cmdargs", out)

    def test_the_community_lands_in_the_odm_not_in_rc_tcpip(self):
        fake = FakeVios()
        rc, _, _ = run(["--community", COMMUNITY, "--apply"], fake)
        self.assertEqual(rc, 0)
        self.assertEqual(fake.cmdargs, {s: SUBCMD for s in S.SUBAGENTS})
        self.assertNotIn(COMMUNITY, fake.files[S.RC_TCPIP])

    def test_chssys_runs_before_the_daemons_are_restarted(self):
        fake = FakeVios()
        run(["--community", COMMUNITY, "--apply"], fake)
        chssys = [i for i, c in enumerate(fake.calls) if "chssys" in c]
        stop = [i for i, c in enumerate(fake.calls) if "stopsrc" in c]
        self.assertTrue(chssys)
        self.assertLess(chssys[0], stop[0])

    def test_startsrc_carries_no_argument_of_its_own(self):
        # startsrc appends -a to the ODM cmdargs: a second copy here would win
        # over the ODM on every boot.
        fake = FakeVios()
        run(["--community", COMMUNITY, "--apply"], fake)
        starts = [c for c in fake.calls if "startsrc" in c]
        self.assertTrue(starts)
        self.assertIn("startsrc -s aixmibd", starts[-1])
        self.assertNotIn('"-c ', starts[-1])

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
        self.assertFalse([c for c in fake.calls
                          if "stopsrc" in c or "chssys" in c or c.startswith("cp /home/padmin")])

    def test_apply_with_no_traps(self):
        fake = FakeVios()
        rc, _, _ = run(["--community", COMMUNITY, "--apply", "--no-traps"], fake)
        self.assertEqual(rc, 0)
        self.assertEqual(S.trap_entries(fake.files[S.CONF]), [])

    def test_no_restart_skips_the_daemons_but_still_sets_the_odm(self):
        fake = FakeVios()
        rc, _, _ = run(["--community", COMMUNITY, "--apply", "--no-restart"], fake)
        self.assertEqual(rc, 0)
        self.assertEqual(fake.services, {s: "inoperative" for s in S.SUBSYSTEMS})
        self.assertEqual(fake.cmdargs, {s: SUBCMD for s in S.SUBAGENTS})

    def test_a_host_that_only_lacks_the_odm_part_rewrites_no_file(self):
        conf, rc_text = configured()
        fake = FakeVios(conf=conf, rc=rc_text)
        rc, out, _ = run(["--community", COMMUNITY, "--apply"], fake)
        self.assertEqual(rc, 0)
        self.assertEqual(fake.cmdargs, {s: SUBCMD for s in S.SUBAGENTS})
        self.assertFalse([c for c in fake.calls if c.startswith("cp /home/padmin")])
        self.assertFalse(fake.puts)

    def test_public_clears_the_odm_cmdargs(self):
        fake = FakeVios(cmdargs={s: "-c oldcomm" for s in S.SUBAGENTS})
        rc, _, _ = run(["--community", "public", "--apply"], fake)
        self.assertEqual(rc, 0)
        self.assertEqual(fake.cmdargs, {s: "" for s in S.SUBAGENTS})


class VerifyTest(unittest.TestCase):
    def test_failed_check_rolls_the_files_and_the_odm_back(self):
        fake = FakeVios(verify_ok=False)
        rc, out, err = run(["--community", COMMUNITY, "--apply"], fake)
        self.assertEqual(rc, 1)
        self.assertEqual(fake.files[S.CONF], ORIG)
        self.assertEqual(fake.files[S.RC_TCPIP], RC)
        self.assertEqual(fake.cmdargs, {s: "" for s in S.SUBAGENTS})
        self.assertIn("rolling back", err)
        self.assertIn("FAIL system", out)

    def test_a_chssys_that_does_not_stick_aborts_the_apply(self):
        fake = FakeVios(chssys_sticks=False)
        rc, _, err = run(["--community", COMMUNITY, "--apply"], fake)
        self.assertEqual(rc, 1)
        self.assertIn("do not hold what chssys wrote", err)
        self.assertEqual(fake.files[S.CONF], ORIG)
        self.assertEqual(fake.files[S.RC_TCPIP], RC)

    def test_a_subagent_running_without_the_community_fails_the_check(self):
        # The ODM is right, but this boot's process was started before it changed:
        # exactly what a stale rc.tcpip argument looks like.
        fake = FakeVios(ps_hides=True)
        rc, out, _ = run(["--community", COMMUNITY, "--apply"], fake)
        self.assertEqual(rc, 1)
        self.assertIn("FAIL cmdargs", out)
        self.assertIn("runs without", out)

    def test_apply_requires_a_community(self):
        fake = FakeVios()
        with self.assertRaises(SystemExit):
            run(["--apply"], fake)
        self.assertEqual(fake.files[S.CONF], ORIG)


class TestModeTest(unittest.TestCase):
    """--test: the snmpinfo checks on their own, with nothing written."""

    def test_a_healthy_host_passes_and_nothing_is_written(self):
        fake = healthy()
        rc, out, _ = run(["--test"], fake)
        self.assertEqual(rc, 0)
        for check in ("cmdargs", "system", "aixmibd", "hostmibd"):
            self.assertIn("ok   %s" % check, out)
        self.assertIn("all checks passed", out)
        self.assertFalse([c for c in fake.calls
                          if "cp " in c or "chssys" in c or "startsrc" in c or "stopsrc" in c])
        self.assertEqual(fake.puts, {})

    def test_without_a_community_it_tests_the_configured_one(self):
        fake = healthy()
        rc, out, _ = run(["--test"], fake)
        self.assertEqual(rc, 0)
        self.assertIn("testing with community '%s'" % COMMUNITY, out)
        self.assertTrue([c for c in fake.calls if '-c "%s"' % COMMUNITY in c])

    def test_a_factory_host_is_tested_with_public(self):
        fake = FakeVios()
        fake.services = {s: "active" for s in S.SUBSYSTEMS}
        rc, out, _ = run(["--test"], fake)
        self.assertEqual(rc, 0)
        self.assertIn("testing with community 'public'", out)
        self.assertTrue([c for c in fake.calls if 'snmpinfo -md -v -c "public" system' in c])

    def test_no_response_fails_the_test(self):
        fake = healthy(verify_ok=False)
        rc, out, _ = run(["--test"], fake)
        self.assertEqual(rc, 1)
        self.assertIn("FAIL system", out)
        self.assertIn("0821-103", out)
        self.assertIn("3 of 4 checks failed", out)

    def test_nosuchname_fails_even_when_snmpinfo_exits_zero(self):
        fake = healthy(bodies={"hostmibd": (fixture("snmpinfo.nosuchname.txt"), 0)})
        rc, out, _ = run(["--test"], fake)
        self.assertEqual(rc, 1)
        self.assertIn("FAIL hostmibd", out)
        self.assertIn("1 of 4 checks failed", out)

    def test_json_test_report(self):
        rc, out, _ = run(["--test", "--json"], healthy())
        report = json.loads(out)
        self.assertEqual(rc, 0)
        self.assertTrue(report["ok"])
        self.assertEqual(report["community"], COMMUNITY)
        self.assertEqual(len(report["verify"]), 4)

    def test_test_and_apply_are_mutually_exclusive(self):
        with self.assertRaises(SystemExit):
            run(["--test", "--apply", "--community", COMMUNITY], healthy())


class CmdargsReadTest(unittest.TestCase):
    """Reading the ODM: an already-correct value must not look like drift."""

    def test_an_odm_that_is_already_right_is_not_drift(self):
        fake = healthy()
        rc, out, _ = run(["--community", COMMUNITY, "--json"], fake)
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)["cmdargs_changes"], [])
        self.assertIn("configuration already matches the plan", run(["--community", COMMUNITY], healthy())[1])

    def test_extra_spacing_in_the_odm_is_not_drift(self):
        fake = healthy(cmdargs={s: "-c   %s" % COMMUNITY for s in S.SUBAGENTS})
        rc, out, _ = run(["--community", COMMUNITY], fake)
        self.assertEqual(rc, 0)
        self.assertIn("configuration already matches the plan", out)

    def test_odmget_wins_over_a_stale_lssrc_row(self):
        fake = healthy(lssrc_cmdargs={s: "-c STALE" for s in S.SUBAGENTS})
        rc, out, _ = run(["--community", COMMUNITY], fake)
        self.assertEqual(rc, 0)
        self.assertIn("configuration already matches the plan", out)

    def test_lssrc_is_the_fallback_when_odmget_returns_nothing(self):
        fake = healthy(odm_absent=True)
        rc, out, _ = run(["--community", COMMUNITY], fake)
        self.assertEqual(rc, 0)
        self.assertIn("configuration already matches the plan", out)

    def test_a_different_community_is_still_drift(self):
        fake = healthy(cmdargs={s: "-c oldcomm" for s in S.SUBAGENTS})
        rc, out, _ = run(["--community", COMMUNITY], fake)
        self.assertEqual(rc, 10)
        self.assertIn("chssys -s aixmibd -a '-c %s'" % COMMUNITY, out)

    def test_the_probe_queries_odmget_for_each_subagent(self):
        fake = healthy()
        run(["--community", COMMUNITY], fake)
        probe = [c for c in fake.calls if "__VS_AGENT__" in c][0]
        for sub in S.SUBAGENTS:
            self.assertIn("odmget -q subsysname=%s SRCsubsys" % sub, probe)


if __name__ == "__main__":
    unittest.main()
