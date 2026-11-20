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


def setUpModule():
    """A failing apply would otherwise sit in the settle loop for a minute."""
    T.SETTLE_SECONDS = 1
    T.SETTLE_PAUSE = 0.2
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
                 odm_absent=False, lssrc_cmdargs=None, quoted_sentinels=False,
                 agent_link="snmpdv3ne", ssw_sticks=True,
                 get_empty=False, dump_empty=False, register_after=0,
                 agent_ip="10.17.10.21", local_ips=("10.17.10.21",), boots_present=True,
                 hostname="vios21", hosts_ips=("172.16.7.154",), dpid2="active",
                 loopback_output="loopback is 127.0.0.1", loopback_rc=0,
                 v1conf="", pkg="  bos.net.tcp.client            7.2.5.0        COMMITTED  TCP",
                 listen_text=("tcp4       0      0  *.161                  *.*                    LISTEN\n"
                              "udp4       0      0  *.161                  *.*"),
                 running_text=("pid=4122\n"
                               "    root  4122     1   0 09:00:00      -  0:07 /usr/sbin/snmpd\n"
                               "lrwxrwxrwx    1 root     system   20 Nov 18 09:00 "
                               "/proc/4122/object/a.out -> /usr/sbin/snmpdv3ne")):
        self.host = "vios1"
        # The real host prints a relative target: `snmpd -> snmpdv3ne`.
        self.agent_link = agent_link
        self.agent_line = ("lrwxrwxrwx    1 root     system            9 Oct 06 12:59 "
                           "/usr/sbin/snmpd -> %s" % agent_link)
        self.ssw_sticks = ssw_sticks           # False: snmpv3_ssw exits 0 and changes nothing
        self.usage_ssw = ("getopt: Not a recognized flag: l\nUsage: /usr/sbin/snmpv3_ssw "
                          "[-e|-n|-1]")
        self.get_empty = get_empty             # True: `-m get` answers nothing at all
        self.dump_empty = dump_empty           # True: `-md` answers nothing either
        self.agent_ip = agent_ip               # what /var/tmp/snmpdv3.log says it initialised from
        self.local_ips = list(local_ips)
        self.boots_present = boots_present     # /etc/snmpd.boots exists
        self.dpid2 = dpid2                     # dpid2 subsystem status on the far side
        self.v1conf = v1conf                   # /etc/snmpd.conf: ls line + active directives
        self.pkg = pkg                         # lslpp for bos.net.tcp.client
        self.loopback_output, self.loopback_rc = loopback_output, loopback_rc
        self.hostname = hostname
        self.hosts_ips = list(hosts_ips)       # what /etc/hosts says the hostname is
        self.register_after = register_after   # verify rounds in which children are absent
        self.verify_rounds = 0
        self.listen_text = listen_text         # netstat, for the DPI2 connect question
        self.running_text = running_text       # ps -ef | grep snmpd
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
        # True: `echo \"X\"` in the root shell prints the quotes, as seen on VIOS 4.1
        self.quoted_sentinels = quoted_sentinels
        self.backups = {}
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
        return (self.backups if path in self.backups else self.files)[path]

    def root(self, cmd, timeout=None):
        self.calls.append(cmd)
        if "__VS_LOOPBACK__" in cmd:
            return self.loopback_rc, "__VS_LOOPBACK__\n" + self.loopback_output
        if "__VS_AGENT__" in cmd:
            return 0, self._probe()
        if "__VS_T_" in cmd:
            if "__VS_T_system__" in cmd:
                self.verify_rounds += 1
            return 0, self._verify(cmd)
        if "snmpd.boots" in cmd and "mv" in cmd:
            if not self.boots_present:
                return 0, "__absent__"
            self.boots_present = False
            if self.local_ips:
                self.agent_ip = self.local_ips[0]      # the agent rebuilds it from this address
            return 0, "__moved__"
        if "snmpv3_ssw" in cmd:
            # Real flags on VIOS 4.1: -e, -n, -1. There is no -l.
            m = re.search(r"snmpv3_ssw\s+(-[en1])\b", cmd)
            target = {"-n": "snmpdv3ne", "-e": "snmpdv3e", "-1": "snmpdv1"}.get(m.group(1) if m else "")
            if target and self.ssw_sticks:
                self.agent_link = target
                self.agent_line = ("lrwxrwxrwx    1 root     system            9 Oct 06 12:59 "
                                   "/usr/sbin/snmpd -> %s" % target)
            return 0, self.usage_ssw if " -l" in cmd else ""
        if "ls -l /usr/sbin/snmpd" in cmd:
            return 0, self.agent_line
        if "chssys" in cmd:
            return 0, self._chssys(cmd)
        if "__VS_CMD__" in cmd:
            return 0, self._cmdargs(cmd)
        if cmd.startswith("mkdir -p"):
            for src, dest in re.findall(r"cp -p (\S+) (\S+)", cmd):
                self.backups[dest] = self.files[src]
            return 0, ""
        if cmd.startswith("cp /home/padmin"):
            return 0, self._install(cmd)
        if cmd.startswith("cp -p"):
            _, _, src, dest = cmd.split()
            self.files[dest] = self.backups[src]
            return 0, ""
        if "stopsrc" in cmd or "startsrc" in cmd:
            if re.search(r"startsrc -s dpid2", cmd):
                self.dpid2 = "active"
            return 0, self._services(cmd)
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
        out = ["__VS_AGENT__", self.agent_line,
               "__VS_LISTEN__", self.listen_text,
               "__VS_RUNNING__", self.running_text,
               "__VS_AGENTIP__", (" 11/18/26 02:04:31 PM -  s_agv123.c(1117) Agent using IP "
                                  "address UDP %s port 0" % self.agent_ip),
               "__VS_LOCALIP__",
               "\n".join("        inet %s netmask 0xffffff00 broadcast 10.0.0.255" % ip
                         for ip in self.local_ips),
               "__VS_V1CONF__", self.v1conf or "ls: 0653-341 no such file",
               "__VS_PKG__", self.pkg,
               "__VS_HOSTS__",
               "\n".join(["hostname=%s" % self.hostname]
                         + ["%s       %s" % (ip, self.hostname) for ip in self.hosts_ips]),
               "__VS_BOOTUP__", "no"]
        for s in S.SUBSYSTEMS:
            name = '"__VS_SVC__%s"' % s if self.quoted_sentinels else "__VS_SVC__" + s
            out += [name, " %s        tcpip      %-8s %s" % (s, 1234, self.services[s])]
        out += ["__VS_SVC__dpid2", " dpid2        tcpip      %-8s %s" % (1234, self.dpid2)]
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

    def _services(self, cmd):
        """Model stopsrc/startsrc, including the `for s in ...` loops the tool uses."""
        names = set(re.findall(r"(?:start|stop)src -s (\w+)", cmd))
        for loop in re.findall(r"for s in ([\w ]+);", cmd):
            names.update(loop.split())
        # The tool scripts stop-then-start in one call, so apply both in order.
        if "stopsrc" in cmd:
            for s in names & set(self.services):
                self.services[s] = "inoperative"
        if "startsrc" in cmd:
            for s in names & set(self.services):
                self.services[s] = "active"
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
        for key in ("system", "snmpmibd", "aixmibd", "hostmibd"):
            head = "__VS_T_%s__" % key
            if head not in cmd:
                continue
            # The sentinel is echoed, so the remainder starts with its closing quote:
            # the command is the next line that mentions snmpinfo.
            rest = cmd.split(head, 1)[1].split("\n")[1:]
            line = next((l for l in rest if "snmpinfo" in l), "")
            getform = "-m get" in line
            if self.verify_rounds <= self.register_after and key in S.SUBAGENTS:
                # A child that could not connect at start keeps trying: for a while
                # the master answers noSuchName for its subtree.
                body, rc = "noSuchName at position 1", 0
            elif not self.verify_ok:
                body, rc = fixture("snmpinfo.noresponse.txt"), 1
            elif key in self.bodies:
                body, rc = self.bodies[key]
            elif getform:
                body, rc = (("", 0) if self.get_empty else (fixture("snmpinfo.%s.txt" % key), 0))
            elif self.dump_empty and key != "system":
                # What the real host did: the master answers, the subagent trees do not.
                body, rc = "", 0
            else:
                body, rc = fixture("snmpinfo.%s.txt" % key), 0
            out += [head, body.rstrip("\n"), "__VS_T_%s_rc__=%d" % (key, rc)]
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
        self.assertTrue([c for c in fake.calls
                         if 'snmpinfo -m get -c "public" 1.3.6.1.2.1.1.1.0' in c])

    def test_no_response_fails_the_test(self):
        fake = healthy(verify_ok=False)
        rc, out, _ = run(["--test"], fake)
        self.assertEqual(rc, 1)
        self.assertIn("FAIL system", out)
        self.assertIn("0821-103", out)
        self.assertIn("4 of 6 checks failed", out)

    def test_nosuchname_fails_even_when_snmpinfo_exits_zero(self):
        fake = healthy(bodies={"hostmibd": (fixture("snmpinfo.nosuchname.txt"), 0)})
        rc, out, _ = run(["--test"], fake)
        self.assertEqual(rc, 1)
        self.assertIn("FAIL hostmibd", out)
        self.assertIn("1 of 6 checks failed", out)

    def test_json_test_report(self):
        rc, out, _ = run(["--test", "--json"], healthy())
        report = json.loads(out)
        self.assertEqual(rc, 0)
        self.assertTrue(report["ok"])
        self.assertEqual(report["community"], COMMUNITY)
        self.assertEqual(len(report["verify"]), 6)

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


class FarSideQuirksTest(unittest.TestCase):
    """What the root shell and this AIX level actually print, as seen on a real VIOS."""

    def test_quoted_sentinels_do_not_become_the_service_status(self):
        # `echo \"X\"` prints the quotes, so the sentinel line arrives quoted and
        # used to leave a lone " as every subsystem's status.
        fake = healthy(quoted_sentinels=True)
        rc, out, _ = run([], fake)
        self.assertEqual(rc, 0)
        self.assertIn("snmpd active", out)
        self.assertNotIn('"', out.split("services")[1].split("\n")[0])

    def test_numeric_aixmib_output_passes(self):
        # VIOS 4.1's snmpinfo prints numeric OIDs instead of aixPageThreshold.
        fake = healthy(bodies={"aixmibd": (fixture("snmpinfo.aixmibd.numeric.txt"), 0)})
        rc, out, _ = run(["--test"], fake)
        self.assertEqual(rc, 0, out)
        self.assertIn("ok   aixmibd", out)

    def test_hostmibd_gets_a_known_instance_first(self):
        fake = healthy()
        rc, out, _ = run(["--test", "--json"], fake)
        self.assertEqual(rc, 0)
        cmds = dict((r["check"], r["command"]) for r in json.loads(out)["verify"])
        self.assertIn("1.3.6.1.2.1.25.1.1.0", cmds["hostmibd"])

    def test_a_failed_get_falls_back_to_the_dump_form(self):
        # dump resolves names through the client's MIB files and is the form IBM
        # documents; get needs no MIB. Either one answering is enough.
        fake = healthy(get_empty=True)
        rc, out, _ = run(["--test", "--json"], fake)
        self.assertEqual(rc, 0, out)
        report = json.loads(out)
        cmds = dict((r["check"], r["command"]) for r in report["verify"])
        self.assertIn("-md -c", cmds["aixmibd"])
        self.assertIn("-md -c", cmds["hostmibd"])

    def test_no_walk_is_ever_asked_for(self):
        # This snmpinfo takes get|next|set|dump; `walk` is not a mode.
        fake = healthy()
        rc, out, _ = run(["--test", "--json"], fake)
        self.assertEqual(rc, 0)
        self.assertNotIn("-m walk", out)
        self.assertNotIn("-m walk", " ".join(fake.calls))

    def test_the_hint_names_registration_when_every_form_is_empty(self):
        fake = healthy(get_empty=True, dump_empty=True)
        rc, out, _ = run(["--test"], fake)
        self.assertEqual(rc, 1)
        self.assertIn("FAIL aixmibd", out)
        self.assertIn("bounce the four daemons in order", out)

    def test_dpid2_is_reported_but_not_blamed(self):
        # dpid2 is inoperative on VIOSes where the child subtrees answer fine, so it
        # is a fact to show, not a diagnosis to draw.
        fake = healthy(dpid2="inoperative", bodies={"aixmibd": ("noSuchName at position 1", 0)})
        rc, out, _ = run(["--test"], fake)
        self.assertEqual(rc, 1)
        self.assertIn("dpid2      inoperative", out)
        self.assertNotIn("dpid2 is", out)
        self.assertNotIn("startsrc -s dpid2", out)

    def test_a_nosuchname_subtree_gets_the_registration_hint(self):
        # What 10.17.10.21 said: the master answers, the subtree is not in its tree.
        fake = healthy(bodies={"aixmibd": ("noSuchName at position 1", 0)})
        rc, out, _ = run(["--test"], fake)
        self.assertEqual(rc, 1)
        self.assertIn("FAIL aixmibd", out)
        self.assertIn("not registered", out)

    def test_the_four_daemons_all_get_a_check(self):
        rc, out, _ = run(["--test", "--json"], healthy())
        self.assertEqual(rc, 0)
        names = [r["check"] for r in json.loads(out)["verify"]]
        self.assertEqual(names, ["agent", "cmdargs", "system", "snmpmibd", "aixmibd", "hostmibd"])

    def test_a_usage_message_is_not_a_value(self):
        fake = healthy(bodies={"aixmibd": ("getopt: bad flag\nUsage: snmpinfo [-m mode]", 0)})
        rc, out, _ = run(["--test"], fake)
        self.assertEqual(rc, 1)
        self.assertIn("FAIL aixmibd", out)

    def test_an_empty_answer_says_so(self):
        fake = healthy(bodies={"hostmibd": ("", 0)})
        rc, out, _ = run(["--test"], fake)
        self.assertEqual(rc, 1)
        self.assertIn("FAIL hostmibd", out)
        self.assertIn("no output", out)


class RestartTest(unittest.TestCase):
    """--restart: bounce the four daemons in order, write nothing, then check them."""

    def test_restart_bounces_in_order_and_verifies(self):
        fake = healthy()
        rc, out, _ = run(["--restart"], fake)
        self.assertEqual(rc, 0)
        self.assertIn("restarted and verified", out)
        stop = [c for c in fake.calls if "stopsrc" in c and "\n" in c][0]
        self.assertLess(stop.index("for s in snmpmibd hostmibd aixmibd"),
                        stop.index("stopsrc -s snmpd"))
        start = [c for c in fake.calls if "startsrc" in c][-1]
        self.assertIn("startsrc -s snmpd", start)
        self.assertIn("startsrc -s aixmibd", start)
        self.assertFalse([c for c in fake.calls if c.startswith("cp ") or "chssys" in c])

    def test_restart_writes_nothing_even_when_the_files_drift(self):
        fake = FakeVios()
        fake.services = {s: "active" for s in S.SUBSYSTEMS}
        rc, _, _ = run(["--restart"], fake)
        self.assertEqual(rc, 0)
        self.assertEqual(fake.files[S.CONF], ORIG)
        self.assertEqual(fake.puts, {})

    def test_restart_waits_for_a_child_that_registers_late(self):
        fake = healthy(register_after=1)
        with unittest.mock.patch.object(T, "SETTLE_PAUSE", 0):
            rc, out, err = run(["--restart"], fake)
        self.assertEqual(rc, 0, out)
        self.assertIn("restarted and verified", out)
        self.assertIn("waiting for the subagents to register", err)
        self.assertEqual(fake.verify_rounds, 2)

    def test_restart_can_bounce_one_child_and_leave_the_master_up(self):
        fake = healthy()
        rc, out, _ = run(["--restart", "--enable", "aixmibd"], fake)
        self.assertEqual(rc, 0, out)
        self.assertIn("bouncing aixmibd, master left running", out)
        bounce = [c for c in fake.calls if "stopsrc" in c][0]
        self.assertIn("for s in aixmibd; do lssrc -s $s >/dev/null 2>&1 && stopsrc -s $s; done", bounce)
        self.assertIn("for s in aixmibd; do startsrc -s $s; done", bounce)
        self.assertFalse([c for c in fake.calls if "stopsrc -s snmpd" in c])

    def test_restart_stands_on_its_own(self):
        with self.assertRaises(SystemExit):
            run(["--restart", "--apply", "--community", COMMUNITY], healthy())
        with self.assertRaises(SystemExit):
            run(["--restart", "--test"], healthy())


class LoopbackTest(unittest.TestCase):
    def test_lookup_timeout_does_not_abort_snmp_tests(self):
        import subprocess

        fake = healthy()
        root = fake.root

        def stalled_lookup(cmd, timeout=None):
            if "host loopback" in cmd:
                self.assertNotIn("__VS_AGENT__", cmd)
                if timeout is None:
                    self.fail("lookup requires a timeout")
                self.assertLessEqual(timeout, 10)
                raise subprocess.TimeoutExpired(cmd, timeout)
            return root(cmd, timeout=timeout)

        fake.root = stalled_lookup
        rc, out, err = run(["--test"], fake)
        self.assertEqual(rc, 0, err)
        self.assertIn("loopback lookup timed out", out)
        self.assertIn("all checks passed", out)

    def test_unresolved_loopback_is_reported_without_editing_hosts(self):
        fake = healthy(loopback_output="host: 0827-801 Host name loopback does not exist.",
                       loopback_rc=1)
        rc, out, _ = run(["--test", "--json"], fake)
        report = json.loads(out)
        self.assertEqual(rc, 0)  # diagnostic, not a substitute for the MIB checks
        self.assertTrue(any("loopback" in s and "/etc/hosts" in s for s in report["findings"]))
        self.assertTrue(any("host loopback" in cmd for cmd in fake.calls))
        self.assertFalse(any("stopsrc" in cmd or "startsrc" in cmd for cmd in fake.calls))

    def test_apply_repairs_missing_alias_preserving_existing_names(self):
        fake = healthy(loopback_output="host: 0827-801 Host name loopback does not exist.",
                       loopback_rc=1)
        fake.files["/etc/hosts"] = "\n127.0.0.1\tlocalhost localname # keep\n192.0.2.5 other\n"
        rc, out, _ = run(["--community", COMMUNITY], fake)
        self.assertEqual(rc, 10, out)
        self.assertIn("/etc/hosts", out)
        self.assertFalse(fake.puts)
        def resolve_on_write(cmd, timeout=None):
            if "__VS_LOOPBACK__" in cmd and "localname loopback" in fake.files["/etc/hosts"]:
                return 0, "__VS_LOOPBACK__\nloopback is 127.0.0.1"
            return FakeVios.root(fake, cmd, timeout)

        fake.root = resolve_on_write
        rc, out, err = run(["--community", COMMUNITY, "--apply"], fake)
        self.assertEqual(rc, 0, err)
        self.assertEqual(fake.files["/etc/hosts"],
                         "\n127.0.0.1\tlocalhost localname loopback # keep\n192.0.2.5 other\n")
        self.assertEqual(set(fake.puts), {".vios_snmp.hosts"})
        self.assertTrue(any("/etc/hosts.bak." in call for call in fake.calls))
        fake.calls.clear()
        fake.puts.clear()
        rc, _, err = run(["--community", COMMUNITY, "--apply"], fake)
        self.assertEqual(rc, 0, err)
        self.assertFalse(fake.puts)
        self.assertFalse(any("stopsrc" in call for call in fake.calls))

    def test_apply_adds_ipv4_alias_when_ipv6_loopback_already_has_it(self):
        ipv6 = "::1                 loopback localhost      # IPv6 loopback (lo0) name/address\n"
        original = "127.0.0.1   localhost\n" + ipv6
        repaired = "127.0.0.1   localhost loopback\n" + ipv6
        fake = healthy(loopback_output="host: 0827-801 Host name loopback does not exist.",
                       loopback_rc=1)
        fake.files["/etc/hosts"] = original

        def resolve_on_write(cmd, timeout=None):
            if "__VS_LOOPBACK__" in cmd and fake.files["/etc/hosts"] == repaired:
                return 0, "__VS_LOOPBACK__\nlocalhost is 127.0.0.1, Aliases: loopback"
            return FakeVios.root(fake, cmd, timeout)

        fake.root = resolve_on_write
        rc, out, err = run(["--community", COMMUNITY, "--apply"], fake)
        self.assertEqual(rc, 0, err)
        self.assertEqual(fake.files["/etc/hosts"], repaired)
        self.assertIn("applied and verified", out)

    def test_apply_leaves_ambiguous_or_already_configured_hosts_alone(self):
        for original in ("127.0.0.1 localhost loopback\n",
                         "127.0.0.1 localhost\n192.0.2.1 loopback\n",
                         "127.0.0.1 localhost\n2001:db8::1 loopback\n",
                         "127.0.0.1 localhost\n127.0.0.1 other\n",
                         "192.0.2.1 other\n"):
            with self.subTest(original=original):
                fake = healthy(loopback_output="not found", loopback_rc=1)
                fake.files["/etc/hosts"] = original
                rc, out, err = run(["--community", COMMUNITY, "--apply"], fake)
                self.assertEqual(rc, 0, err)
                self.assertIn("resolver order", out)
                self.assertFalse(fake.puts)

    def test_unresolved_after_edit_restores_hosts_without_restarting(self):
        fake = healthy(loopback_output="not found", loopback_rc=1)
        original = "127.0.0.1 localhost"
        fake.files["/etc/hosts"] = original
        rc, _, err = run(["--community", COMMUNITY, "--apply"], fake)
        self.assertEqual(rc, 1)
        self.assertIn("still does not resolve", err)
        self.assertEqual(fake.files["/etc/hosts"], original)
        self.assertFalse(any("stopsrc" in cmd for cmd in fake.calls))

    def test_snmp_verification_failure_rolls_back_loopback_repair(self):
        fake = healthy(loopback_output="not found", loopback_rc=1, verify_ok=False)
        original = "127.0.0.1 localhost"
        fake.files["/etc/hosts"] = original

        def resolve_on_write(cmd, timeout=None):
            if "__VS_LOOPBACK__" in cmd and fake.files["/etc/hosts"] != original:
                return 0, "__VS_LOOPBACK__\nloopback is 127.0.0.1"
            return FakeVios.root(fake, cmd, timeout)

        fake.root = resolve_on_write
        rc, _, err = run(["--community", COMMUNITY, "--apply"], fake)
        self.assertEqual(rc, 1)
        self.assertIn("configuration rolled back", err)
        self.assertEqual(fake.files["/etc/hosts"], original)

    def test_resolved_loopback_is_shown_without_a_warning(self):
        rc, out, _ = run([], healthy())
        self.assertEqual(rc, 0)
        self.assertIn("loopback   127.0.0.1", out)
        self.assertNotIn("check /etc/hosts", out)


class AgentLinkTest(unittest.TestCase):
    """/usr/sbin/snmpd must resolve to snmpdv3ne (or snmpdv3e): the file edited depends on it."""

    def test_a_relative_target_resolves_under_usr_sbin(self):
        line = "lrwxrwxrwx    1 root     system   9 Oct 06 12:59 /usr/sbin/snmpd -> snmpdv3ne"
        self.assertEqual(T.agent_target(line), "/usr/sbin/snmpdv3ne")

    def test_an_absolute_target_is_kept(self):
        line = "lrwxrwxrwx 1 root system 9 Nov  9 2015 /usr/sbin/snmpd -> /usr/sbin/snmpdv3ne"
        self.assertEqual(T.agent_target(line), "/usr/sbin/snmpdv3ne")

    def test_a_plain_file_is_not_a_symlink(self):
        line = "-rwxr-xr-x 1 root system 9 Nov  9 2015 /usr/sbin/snmpd"
        self.assertEqual(T.agent_target(line), "")
        self.assertFalse(T.agent_state("")[0])

    def test_the_v3_agent_is_accepted(self):
        self.assertEqual(T.agent_state("/usr/sbin/snmpdv3ne"), (True, ""))

    def test_the_encrypted_agent_is_accepted_with_a_note(self):
        ok, msg = T.agent_state("/usr/sbin/snmpdv3e")
        self.assertTrue(ok)
        self.assertIn("snmp.crypto", msg)

    def test_another_agent_is_refused(self):
        ok, msg = T.agent_state("/usr/sbin/snmpdv1")
        self.assertFalse(ok)
        self.assertIn("not snmpdv3ne", msg)

    def test_recon_shows_the_resolved_target(self):
        rc, out, _ = run([], FakeVios())
        self.assertEqual(rc, 0)
        self.assertIn("agent      /usr/sbin/snmpdv3ne", out)

    def test_the_v1_agent_message_names_its_own_config(self):
        ok, msg = T.agent_state("/usr/sbin/snmpdv1")
        self.assertFalse(ok)
        self.assertIn("/etc/snmpd.conf", msg)
        self.assertIn("has no effect", msg)

    def test_recon_reports_the_agent_address_without_judging_it(self):
        # On a VIOS the address clients use is often a NET (virtual) one, so the
        # agent's real-interface address differing from it means nothing.
        fake = healthy(agent_ip="172.16.7.154", local_ips=("10.17.10.21", "172.16.7.154"))
        rc, out, _ = run([], fake)
        self.assertEqual(rc, 0)
        self.assertIn("agent ip   172.16.7.154", out)
        self.assertIn("local ips  10.17.10.21, 172.16.7.154", out)
        self.assertIn("host       vios21 -> 172.16.7.154 (from /etc/hosts)", out)
        self.assertNotIn("stale", out)
        self.assertNotIn("--reset-boots", out)

    def test_reset_boots_moves_the_file_and_restarts(self):
        fake = healthy(agent_ip="172.16.7.154")
        rc, out, err = run(["--reset-boots"], fake)
        self.assertEqual(rc, 0, err)
        self.assertIn("/etc/snmpd.boots moved aside", out)
        self.assertIn("reset and verified", out)
        self.assertFalse(fake.boots_present)
        self.assertEqual(fake.agent_ip, "10.17.10.21")
        self.assertIn("stopsrc -s snmpd", " ".join(fake.calls))

    def test_reset_boots_stands_on_its_own(self):
        with self.assertRaises(SystemExit):
            run(["--reset-boots", "--restart"], healthy())

    def test_a_leftover_v1_config_is_shown(self):
        # Nothing else in the report would reveal /etc/snmpd.conf.
        fake = healthy(v1conf="-rw-r--r--    1 root     system   4294 Nov 18 2024  "
                              "/etc/snmpd.conf\n snmpd  10.1.1.1  public")
        rc, out, _ = run([], fake)
        self.assertEqual(rc, 0)
        self.assertIn("v1 conf    -rw-r--r--", out)
        self.assertIn("public", out.split("v1 conf")[1].split("\n")[0])

    def test_an_absent_v1_config_is_not_reported(self):
        rc, out, _ = run([], healthy())
        self.assertEqual(rc, 0)
        self.assertNotIn("v1 conf", out)
        self.assertIn("snmp pkg   bos.net.tcp.client 7.2.5.0", out)

    def test_recon_shows_the_listener_and_the_running_agent(self):
        rc, out, _ = run([], FakeVios())
        self.assertEqual(rc, 0)
        self.assertIn("listen     tcp4", out)
        running = out.split("running")[1].split("\n")[0]
        self.assertIn("4122", running)
        self.assertIn("/usr/sbin/snmpdv3ne", running)      # from /proc, not argv[0]
        self.assertIn("since 09:00:00", running)

    def test_the_probe_never_asks_snmpv3_ssw_for_l(self):
        # VIOS 4.1 / AIX 7 accept -e, -n and -1 only; -l prints the usage text.
        fake = healthy()
        run([], fake)
        self.assertFalse([c for c in fake.calls if "snmpv3_ssw" in c and " -l" in c])

    def test_a_failed_verification_puts_the_previous_agent_back(self):
        fake = healthy(agent_link="/usr/sbin/snmpdv1", verify_ok=False)
        rc, _, err = run(["--community", COMMUNITY, "--apply"], fake)
        self.assertEqual(rc, 1)
        self.assertEqual(fake.agent_link, "snmpdv1")
        self.assertIn("back at /usr/sbin/snmpdv1", err)
        self.assertIn("snmpv3_ssw -1", " ".join(fake.calls))

    def test_test_mode_fails_on_the_wrong_agent(self):
        fake = healthy(agent_link="/usr/sbin/snmpdv1")
        rc, out, _ = run(["--test"], fake)
        self.assertEqual(rc, 1)
        self.assertIn("FAIL agent", out)

    def test_plan_offers_the_snmpv3_ssw_fix(self):
        fake = healthy(agent_link="/usr/sbin/snmpdv1")
        rc, out, _ = run(["--community", COMMUNITY, "--json"], fake)
        report = json.loads(out)
        self.assertEqual(rc, 10)
        self.assertEqual(report["agent_change"]["command"], "snmpv3_ssw -n")
        self.assertEqual(report["agent_change"]["before"], "/usr/sbin/snmpdv1")
        self.assertIn("agent link  (1 change)", run(["--community", COMMUNITY], healthy(agent_link="/usr/sbin/snmpdv1"))[1])

    def test_apply_switches_the_link_with_snmpv3_ssw(self):
        fake = healthy(agent_link="/usr/sbin/snmpdv1")
        rc, out, err = run(["--community", COMMUNITY, "--apply"], fake)
        self.assertEqual(rc, 0, err)
        self.assertEqual(fake.agent_link, "snmpdv3ne")
        self.assertIn("snmpv3_ssw -n: /usr/sbin/snmpd -> /usr/sbin/snmpdv3ne", out)
        ssw = [i for i, c in enumerate(fake.calls) if "snmpv3_ssw -n" in c]
        stop = [i for i, c in enumerate(fake.calls) if "stopsrc" in c]
        self.assertTrue(ssw)
        self.assertLess(ssw[0], stop[0])          # the link before the daemons come back
        self.assertIn("ok   agent", out)

    def test_apply_aborts_when_the_switch_does_not_take(self):
        fake = healthy(agent_link="/usr/sbin/snmpdv1", ssw_sticks=False)
        rc, _, err = run(["--community", COMMUNITY, "--apply"], fake)
        self.assertEqual(rc, 1)
        self.assertIn("not snmpdv3ne", err)
        self.assertFalse([c for c in fake.calls if "chssys" in c or c.startswith("cp ")])

    def test_test_mode_never_switches_the_link(self):
        fake = healthy(agent_link="/usr/sbin/snmpdv1")
        rc, _, _ = run(["--test"], fake)
        self.assertEqual(rc, 1)
        self.assertFalse([c for c in fake.calls if "snmpv3_ssw -n" in c])

    def test_the_encrypted_agent_is_reported_but_not_blocked(self):
        fake = healthy(agent_link="snmpdv3e")
        rc, out, _ = run(["--test"], fake)
        self.assertEqual(rc, 0)
        self.assertIn("ok   agent", out)
        self.assertIn("snmp.crypto", out)


if __name__ == "__main__":
    unittest.main()
