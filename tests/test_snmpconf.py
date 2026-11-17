"""Edits to /etc/snmpdv3.conf and /etc/rc.tcpip, checked against the real files.

The golden case is a factory VIOS file plus the hand-made configuration that runs
on the lab VIOS: the rendered result must be functionally identical to that file
(the two files are allowed to differ in whitespace, comments and therefore line
order, since snmpdv3.conf states that entries are not order-dependent).
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
import vioslib.snmpconf as S  # noqa: E402

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


class GoldenTest(unittest.TestCase):
    def setUp(self):
        self.out, self.changes = S.conf_desired(ORIG, community=COMMUNITY)

    def test_matches_the_hand_made_file(self):
        self.assertEqual(without_traps(self.out), without_traps(ADJUSTED))

    def test_trap_entries_are_kept(self):
        self.assertEqual(S.trap_entries(self.out), S.trap_entries(ORIG))

    def test_prologue_is_untouched(self):
        # Everything above the first active directive is IBM's header and the
        # directive documentation; the tool must never write into it.
        first = [i for i, l in enumerate(ORIG.splitlines())
                 if l and l[0] not in "#*" and l.split()[0] in S.DIRECTIVES][0]
        self.assertEqual(self.out.splitlines()[:first], ORIG.splitlines()[:first])

    def test_file_ends_with_a_newline(self):
        self.assertTrue(self.out.endswith("\n"))
        self.assertFalse(self.out.endswith("\n\n"))

    def test_the_public_defaults_are_gone(self):
        # TARGET_PARAMETERS legitimately still names public: trap directives are
        # left alone by default and only reported.
        entries = S.Conf(self.out).entries()
        groups = [f for i, d, f in entries if d == "VACM_GROUP" and len(f) > 2]
        self.assertEqual([g[2] for g in groups], [COMMUNITY])
        communities = [f[0] for i, d, f in entries if d == "COMMUNITY"]
        self.assertEqual(communities, [COMMUNITY])
        views = [f for i, d, f in entries if d == "VACM_VIEW"]
        self.assertFalse([v for v in views if v[1] == "internet" and v[3] != "included"])

    def test_aixmibd_subtree_is_visible(self):
        views = {f[1]: f[3] for i, d, f in S.Conf(self.out).entries("VACM_VIEW")}
        self.assertEqual(views[S.AIX_SUBTREE], "included")
        self.assertEqual(views["internet"], "included")

    def test_only_the_expected_lines_change(self):
        touched = sorted(c.line for c in self.changes)
        # group, commented view, two exclusions, commented community: 5 lines, no rewrite
        self.assertEqual(touched, [144, 146, 151, 156, 166])

    def test_idempotent(self):
        again, changes = S.conf_desired(self.out, community=COMMUNITY)
        self.assertEqual(changes, [])
        self.assertEqual(again, self.out)


class EditTest(unittest.TestCase):
    def test_commented_community_is_reactivated_in_place(self):
        out, changes = S.conf_desired(ORIG, community="s3cret")
        before = ORIG.splitlines()
        line = [i for i, l in enumerate(before)
                if l.lstrip("#* ").startswith("COMMUNITY") and len(l.split()) >= 6][0]
        self.assertEqual(out.splitlines()[line].split(), S.community_entry("s3cret").split())

    def test_managers_become_source_acls(self):
        out, _ = S.conf_desired(ORIG, community="c", managers=[S.normalize_manager("10.20.0.10"),
                                                               S.normalize_manager("10.30.0.0/24")])
        comms = [f for i, d, f in S.Conf(out).entries("COMMUNITY")]
        self.assertEqual([(f[0], f[3], f[4]) for f in comms],
                         [("c", "10.20.0.10", "255.255.255.255"), ("c", "10.30.0.0", "255.255.255.0")])

    def test_extra_active_community_is_disabled(self):
        text = ORIG.replace("VACM_ACCESS", "COMMUNITY old old noAuthNoPriv 0.0.0.0 0.0.0.0 -\n\nVACM_ACCESS")
        out, _ = S.conf_desired(text, community="c")
        active = [f[0] for i, d, f in S.Conf(out).entries("COMMUNITY")]
        self.assertEqual(active, ["c"])

    def test_no_traps_comments_all_three(self):
        out, _ = S.conf_desired(ORIG, community="c", no_traps=True)
        self.assertEqual(S.trap_entries(out), [])
        active = [d for i, d, f in S.Conf(out).entries()]
        for d in S.TRAP_DIRECTIVES:
            self.assertNotIn(d, active)

    def test_v3_mibs_can_stay_excluded(self):
        out, _ = S.conf_desired(ORIG, community="c", v3_mibs="excluded")
        views = {f[1]: f[3] for i, d, f in S.Conf(out).entries("VACM_VIEW")}
        self.assertEqual(views[S.V3_SUBTREE], "excluded")

    def test_usm_entries_are_left_alone(self):
        text = ORIG.replace("VACM_GROUP", "USM_USER admin - HMAC-MD5 abc DES def L -\n\nVACM_GROUP")
        out, _ = S.conf_desired(text, community="c")
        self.assertIn("USM_USER admin - HMAC-MD5 abc DES def L -", out)

    def test_findings_report_stale_trap_community(self):
        out, _ = S.conf_desired(ORIG, community=COMMUNITY)
        notes = " ".join(S.findings(out))
        self.assertIn("TARGET_PARAMETERS", notes)
        self.assertIn("public", notes)
        self.assertIn("3 trap directive(s)", notes)

    def test_manager_normalisation(self):
        self.assertEqual(S.normalize_manager("10.20.0.10"), ("10.20.0.10", "255.255.255.255"))
        self.assertEqual(S.normalize_manager("10.20.0.0/24"), ("10.20.0.0", "255.255.255.0"))
        self.assertEqual(S.normalize_manager("0.0.0.0/0"), ("0.0.0.0", "0.0.0.0"))
        self.assertRaises(ValueError, S.normalize_manager, "10.0.0.0/33")


class RcTcpipTest(unittest.TestCase):
    def setUp(self):
        self.out, self.changes = S.rc_desired(RC, community=COMMUNITY)

    def test_all_four_are_started_at_boot(self):
        self.assertEqual(S.rc_autostart(self.out), {s: True for s in S.SUBSYSTEMS})
        self.assertEqual(S.rc_autostart(RC), {s: False for s in S.SUBSYSTEMS})

    def test_subagents_get_the_community_as_cmdargs(self):
        # rc.tcpip starts daemons with `startsrc -s <cmd> -a "$3"`, so the ODM
        # cmdargs do not apply and the subagents would answer `public`.
        for sub in S.SUBAGENTS:
            self.assertIn('start /usr/sbin/%s "$src_running" "-c %s"' % (sub, COMMUNITY), self.out)
        self.assertIn('start /usr/sbin/snmpd "$src_running"', self.out)

    def test_public_needs_no_argument(self):
        out, _ = S.rc_desired(RC, community="public")
        self.assertIn('start /usr/sbin/hostmibd "$src_running"', out)

    def test_dpid2_and_unrelated_daemons_untouched(self):
        self.assertIn("#start /usr/sbin/dpid2", self.out)
        self.assertIn("start /usr/sbin/inetd", self.out)   # already active in the fixture
        self.assertIn("start /usr/sbin/syslogd", self.out)

    def test_missing_start_line_is_inserted_before_the_wait(self):
        text = "\n".join(l for l in RC.splitlines() if "aixmibd" not in l) + "\n"
        out, _ = S.rc_desired(text, community=COMMUNITY)
        lines = out.splitlines()
        self.assertTrue(S.rc_autostart(out)["aixmibd"])
        self.assertLess(lines.index('start /usr/sbin/aixmibd "$src_running" "-c %s"' % COMMUNITY),
                        [i for i, l in enumerate(lines) if "Wait for srcmstr" in l][0])

    def test_only_four_lines_change(self):
        self.assertEqual(len(self.changes), 4)
        self.assertEqual(S.rc_desired(self.out, community=COMMUNITY)[1], [])


if __name__ == "__main__":
    unittest.main()
