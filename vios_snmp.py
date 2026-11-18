#!/usr/bin/env python3
"""Configure the SNMPv1 agent on a VIOS: /etc/snmpdv3.conf, /etc/rc.tcpip, the SRC
subsystems, the services, and prove it.

  vios_snmp.py --host vios1 --community 'CHANGEME'                    # plan only
  vios_snmp.py --host vios1 --community 'CHANGEME' --apply            # write, restart, verify
  vios_snmp.py --host vios1                                          # recon: report only

The agent, never the traps: NOTIFY / TARGET_ADDRESS / TARGET_PARAMETERS are
reported and left alone (--no-traps disables them).

Why /etc/snmpdv3.conf even for SNMPv1: /usr/sbin/snmpd is a symlink to
snmpdv3ne on VIOS, and that agent serves SNMPv1, v2c and v3 from the same file.
The two community-related things it needs are a COMMUNITY line and an
SNMPv1 security group whose security-name matches it.

Why the subagents' community goes into the ODM and not into rc.tcpip: snmpmibd,
hostmibd and aixmibd take it as `-c <name>` on their own command line, and the
supported way to hand it to them is the SRC subsystem object, set with chssys
(IBM technote 884646). rc.tcpip then starts them with a plain
`startsrc -s <cmd> -a ""`, which appends nothing to the stored cmdargs, so one
copy of the community in the ODM serves both the manual start and the reboot.

Exit codes: 0 in sync (or applied and verified), 10 drift found in plan mode,
1 error. --apply rolls the files and the ODM cmdargs back if a check fails.
"""

import argparse
import json
import os
import shutil
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import vioslib.snmpconf as S          # noqa: E402
import vioslib.vios as V              # noqa: E402

CONF = S.CONF
RC_TCPIP = S.RC_TCPIP
PROBE_TIMEOUT = 120


def log(msg):
    sys.stderr.write(msg + "\n")


# ------------------------------------------------------------------- far side

def cmdargs_block(out, subs):
    """{subsystem: cmdargs} from the __VS_CMD__<sub> blocks of a probe script."""
    res = {}
    for sub in subs:
        m = out.split("__VS_CMD__" + sub, 1)
        res[sub] = S.cmdargs_parse(m[1].strip().split("\n")[0]) if len(m) == 2 else ""
    return res


def read_cmdargs(v, subs):
    """The cmdargs stored in the SRC subsystem object: what the next start will use."""
    script = "\n".join('echo "__VS_CMD__%s"\nlssrc -Ss %s 2>&1 | tail -1' % (s, s) for s in subs)
    rc, out = v.root(script, timeout=PROBE_TIMEOUT)
    if rc != 0:
        raise V.Abort("%s: cannot read the SRC cmdargs: %s" % (v.host, out.strip()[-400:]))
    return cmdargs_block(out, subs)


def probe(v):
    """One root round trip: everything the plan needs to know about this VIOS."""
    script = "\n".join([
        "echo __VS_AGENT__",
        "ls -l /usr/sbin/snmpd 2>&1",
        "echo __VS_BOOTUP__",
        "lsattr -El inet0 -a bootup_option -F value 2>&1",
        "for s in %s; do echo \\\"__VS_SVC__$s\\\"; lssrc -s $s 2>&1 | tail -1; done" % " ".join(S.SUBSYSTEMS),
        "echo __VS_SVC__dpid2",
        "lssrc -s dpid2 2>&1 | tail -1",
        "for s in %s; do echo \\\"__VS_CMD__$s\\\"; lssrc -Ss $s 2>&1 | tail -1; done" % " ".join(S.SUBAGENTS),
        "echo __VS_CONF__",
        "cat %s" % CONF,
        "echo __VS_RC__",
        "cat %s" % RC_TCPIP,
        "echo __VS_END__",
    ])
    rc, out = v.root(script, timeout=PROBE_TIMEOUT)
    if rc != 0 and "__VS_END__" not in out:
        raise V.Abort("%s: cannot read the SNMP configuration: %s" % (v.host, out.strip()[-400:]))

    def block(start, end):
        a = out.find(start)
        b = out.find(end, a + 1) if a >= 0 else -1
        return out[a + len(start):b].strip("\n") if a >= 0 and b > a else ""

    agent = block("__VS_AGENT__", "__VS_BOOTUP__").strip().split("\n")[0]
    bootup = block("__VS_BOOTUP__", "__VS_SVC__snmpd").strip().split("\n")[0]
    svc = {}
    raw = out[:out.find("__VS_CONF__")] if "__VS_CONF__" in out else ""
    for sub in S.SUBSYSTEMS + ("dpid2",):
        m = raw.split("__VS_SVC__" + sub, 1)
        if len(m) == 2:
            line = m[1].strip().split("\n")[0].strip()
            if "not on file" in line or not line:
                svc[sub] = "undefined"
            else:
                svc[sub] = line.split()[-1]
        else:
            svc[sub] = "unknown"
    return {
        "level": V.level(v),
        "agent": agent,
        "bootup_option": bootup,
        "services": svc,
        # The subagents' community lives in the SRC subsystem object, so read the
        # cmdargs that are in force now: that is what chssys would change.
        "cmdargs": cmdargs_block(raw, S.SUBAGENTS),
        "dpid2": svc.get("dpid2", "unknown"),
        "conf": block("__VS_CONF__", "__VS_RC__") + "\n",
        "rc_tcpip": block("__VS_RC__", "__VS_END__") + "\n",
    }


def run_services(v, enabled, stop=False):
    """Stop subagents then the agent, start the agent then the subagents.

    Every start is guarded by `lssrc`, so callers can use this both to bounce a
    changed configuration and to start daemons that were simply not running.
    The starts are plain `startsrc -s <sub>`: the community is the -c in the
    ODM cmdargs set by chssys, and startsrc with no -a appends nothing to it.
    """
    subs = [s for s in S.SUBAGENTS if s in enabled]
    if stop:
        lines = []
        if subs:
            lines.append("for s in %s; do lssrc -s $s >/dev/null 2>&1 && stopsrc -s $s; done" % " ".join(subs))
        lines += [
            "lssrc -s snmpd >/dev/null 2>&1 && stopsrc -s snmpd",
            "i=0",
            "while lssrc -s snmpd 2>/dev/null | grep -q active; do sleep 1; i=$((i+1)); [ $i -ge 30 ] && break; done",
        ]
        rc, out = v.root("\n".join(lines), timeout=180)
        if rc != 0:
            raise V.Abort("stopping the SNMP daemons failed: %s" % out.strip()[-400:])

    lines = [
        "lssrc -s snmpd 2>/dev/null | grep -q active || startsrc -s snmpd",
        "i=0",
        "while ! lssrc -s snmpd 2>/dev/null | grep -q active; do sleep 1; i=$((i+1)); [ $i -ge 30 ] && break; done",
    ]
    for sub in subs:
        lines.append("lssrc -s %s 2>/dev/null | grep -q active || startsrc -s %s" % (sub, sub))
    lines.append("sleep 3")
    rc, out = v.root("\n".join(lines), timeout=240)
    if rc != 0 or "0513-" in out:
        raise V.Abort("starting the SNMP daemons failed: %s" % out.strip()[-600:])
    return out


def verify_cmdargs(v, subs, desired):
    """One check: the ODM cmdargs match the plan and the running subagents carry them.

    Neither half alone proves it. The ODM says what the *next* start will use, so
    it is what a reboot gets; the process says what this boot actually loaded. The
    technote checks both, with `ps -ef | grep mibd` and `lssrc -Ss`.
    """
    lines = ["echo __VS_PS__", "ps -ef | grep '[m]ibd'"]
    for sub in subs:
        lines += ['echo "__VS_CMD__%s"' % sub, "lssrc -Ss %s 2>&1 | tail -1" % sub]
    rc, out = v.root("\n".join(lines), timeout=PROBE_TIMEOUT)
    ps = out.split("__VS_CMD__")[0]
    ps = ps.split("__VS_PS__", 1)[1] if "__VS_PS__" in ps else ""
    odm = cmdargs_block(out, subs)

    problems = []
    for sub in subs:
        want = desired.get(sub, "")
        if odm.get(sub, "") != want:
            problems.append("%s ODM cmdargs %r, wanted %r" % (sub, odm.get(sub, ""), want))
    for sub in subs:
        want = desired.get(sub, "")
        proc = [l for l in ps.splitlines() if "/usr/sbin/" + sub in l]
        if not proc:
            problems.append("%s is not running" % sub)
        elif want and want not in " ".join(proc):
            problems.append("%s runs without %r: %s" % (sub, want, proc[0].strip()))
    return {
        "check": "cmdargs",
        "command": "lssrc -Ss <sub>; ps -ef | grep mibd",
        "ok": not problems,
        "rc": 0 if not problems else 1,
        "output": ("; ".join(problems) or
                   ", ".join("%s %s" % (s, odm.get(s, "") or "(none)") for s in subs))[:400],
    }


def verify(v, community, enabled, cmdargs):
    """Prove the agent answers on 161, that the subagents carry the community, and that their MIBs are there."""
    q = community or "public"
    subs = [s for s in S.SUBAGENTS if s in enabled]
    tests = [("system", 'snmpinfo -md -v -c "%s" system' % q, "sysDescr")]
    if "aixmibd" in subs:
        tests.append(("aixmibd", 'snmpinfo -md -c "%s" aixpagingspace' % q, "aixPageThreshold"))
    if "hostmibd" in subs:
        tests.append(("hostmibd", 'snmpinfo -md -c "%s" 1.3.6.1.2.1.25.1.1.0' % q, None))

    script = []
    for key, cmd, _ in tests:
        script += ['echo "__VS_T_%s__"' % key, "(%s) 2>&1" % cmd, 'echo "__VS_T_%s_rc__=$?"' % key]
    rc, out = v.root("\n".join(script), timeout=180)

    results = []
    for key, cmd, needle in tests:
        head = "__VS_T_%s__" % key
        mrc = out.split("__VS_T_%s_rc__=" % key, 1)
        body = out.split(head, 1)[1].split("__VS_T_%s_rc__=" % key, 1)[0] if head in out else ""
        code = int(mrc[1].split()[0]) if len(mrc) == 2 and mrc[1].split() else 1
        ok = code == 0 and bool(body.strip())
        if ok and needle:
            ok = needle in body
        if ok and needle is None:
            ok = "noSuchName" not in body and "Timeout" not in body
        results.append({"check": key, "command": cmd, "ok": ok, "rc": code,
                        "output": body.strip()[:400]})
    if subs:
        # First, so a wrong community on the subagents is named as the cause
        # rather than showing up as an empty aixMIB subtree.
        results.insert(0, verify_cmdargs(v, subs, cmdargs))
    return results


# --------------------------------------------------------------------- report

def show_probe(p, host, args):
    print("%s  (VIOS %s)" % (host, p["level"]))
    print("  %-10s %s" % ("agent", p["agent"] or "?"))
    print("  %-10s %s" % ("services", ", ".join("%s %s" % (s, p["services"][s]) for s in S.SUBSYSTEMS)))
    auto = S.rc_autostart(p["rc_tcpip"])
    print("  %-10s %s" % ("at boot", ", ".join("%s %s" % (s, "yes" if auto[s] else "no") for s in S.SUBSYSTEMS)))
    print("  %-10s %s" % ("mibd args", ", ".join("%s %s" % (s, p["cmdargs"].get(s) or "(none)")
                                                for s in S.SUBAGENTS)))
    if p["bootup_option"] and p["bootup_option"] != "no":
        print("  %-10s inet0 bootup_option=%s: rc.tcpip skips the SRC start path" % ("note", p["bootup_option"]))
    comms = [f for i, d, f in S.Conf(p["conf"]).entries("COMMUNITY") if f]
    print("  %-10s %s" % ("communities", ", ".join(f[0] for f in comms) or "none active"))
    groups = [f for i, d, f in S.Conf(p["conf"]).entries("VACM_GROUP") if len(f) > 2]
    print("  %-10s %s" % ("groups", ", ".join("%s %s %s" % (f[0], f[1], f[2]) for f in groups) or "none"))


def show_changes(title, changes):
    print("\n%s  (%d change%s)" % (title, len(changes), "" if len(changes) == 1 else "s"))
    for ch in changes:
        print("  %s line %d: %s" % (ch.path, ch.line, ch.why))
        for dl in ch.diff().split("\n"):
            print("    " + dl)


def show_cmdargs(changes):
    """The chssys plan: one SRC subsystem object per changed subagent."""
    print("\nSRC cmdargs  (%d change%s)" % (len(changes), "" if len(changes) == 1 else "s"))
    for sub, before, after in changes:
        print("  %s" % S.chssys_command(sub, after))
        print("    - cmdargs %s" % (before or "(empty)"))
        print("    + cmdargs %s" % (after or "(empty: the subagent answers public)"))


# ----------------------------------------------------------------------- main

def build(v, args):
    """Read the VIOS and compute the desired files and SRC cmdargs. No writes."""
    p = probe(v)
    enabled = tuple(s for s in S.SUBSYSTEMS if s in args.enable)
    managers = [S.normalize_manager(m) for m in args.manager]
    conf_new, conf_changes = S.conf_desired(
        p["conf"], community=args.community, managers=managers,
        v3_mibs=args.v3_mibs, aix_mibs=args.aix_mibs, no_traps=args.no_traps, name=CONF)
    # The community belongs in the ODM, never in the boot script.
    rc_new, rc_changes = S.rc_desired(p["rc_tcpip"], enabled=enabled, name=RC_TCPIP)
    cmdargs = S.cmdargs_desired(args.community, enabled)
    cmd_changes = S.cmdargs_changes(p["cmdargs"], cmdargs) if args.community else []
    return p, enabled, conf_new, conf_changes, rc_new, rc_changes, cmdargs, cmd_changes


def backup(v):
    """Back up both files twice: next to them for the next admin, and per run for rollback."""
    ts = time.strftime("%Y%m%d%H%M%S")
    keep = "/home/padmin/.vios_snmp-%s" % ts
    rc, out = v.root("mkdir -p %s && cp -p %s %s/snmpdv3.conf.bak && cp -p %s %s/rc.tcpip.bak && "
                     "cp -p %s %s.bak.%s && cp -p %s %s.bak.%s"
                     % (keep, CONF, keep, RC_TCPIP, keep, CONF, CONF, ts, RC_TCPIP, RC_TCPIP, ts))
    if rc != 0:
        raise V.Abort("cannot back up the configuration: %s" % out.strip()[-400:])
    print("  backed up to %s (and %s.bak.%s, %s.bak.%s)" % (keep, CONF, ts, RC_TCPIP, ts))
    return keep


def install_files(v, conf_new, rc_new):
    """Stage, upload, cp into /etc as root, then read both files back."""
    tmp = tempfile.mkdtemp(prefix="vios_snmp.")
    try:
        staged = {}
        for path, text in ((CONF, conf_new), (RC_TCPIP, rc_new)):
            name = ".vios_snmp." + os.path.basename(path)
            local = os.path.join(tmp, name)
            with open(local, "w") as f:
                f.write(text)
            staged[path] = name
            v.put(local, "/home/padmin")

        # cp over the existing inode keeps root:system and 644; /etc is root-only.
        rc, out = v.root("cp /home/padmin/%s %s && cp /home/padmin/%s %s; r=$?; "
                         "rm -f /home/padmin/%s /home/padmin/%s; exit $r"
                         % (staged[CONF], CONF, staged[RC_TCPIP], RC_TCPIP, staged[CONF], staged[RC_TCPIP]))
        if rc != 0:
            raise V.Abort("cannot install the new configuration: %s" % out.strip()[-400:])

        # Read the files back: cp reporting success is not proof the bytes landed.
        for path, wanted in ((CONF, conf_new), (RC_TCPIP, rc_new)):
            got = v.root_read(path)
            if got.rstrip("\n") != wanted.rstrip("\n"):
                raise V.Abort("%s does not hold what was written" % path)
    finally:
        # The staged copies carry the community; leave nothing behind in TMPDIR.
        shutil.rmtree(tmp, ignore_errors=True)


def chssys_set(v, values):
    """chssys each subsystem to the given cmdargs, then read the ODM back.

    chssys exiting 0 is not proof: `lssrc -Ss` reads the stored value, and that
    is what the next start of the daemon will use.
    """
    if not values:
        return
    rc, out = v.root("\n".join(S.chssys_command(sub, a) for sub, a in sorted(values.items())),
                     timeout=120)
    if rc != 0:
        raise V.Abort("chssys failed: %s" % out.strip()[-400:])
    now = read_cmdargs(v, sorted(values))
    wrong = [(s, now.get(s, ""), a) for s, a in sorted(values.items()) if now.get(s, "") != a]
    if wrong:
        raise V.Abort("the ODM cmdargs do not hold what chssys wrote: %s"
                      % ", ".join("%s %r (wanted %r)" % w for w in wrong))


def apply_cmdargs(v, cmd_changes):
    """Set the ODM cmdargs; returns [(subsystem, cmdargs_before)] so a failed check can undo it."""
    chssys_set(v, dict((sub, after) for sub, before, after in cmd_changes))
    return [(sub, before) for sub, before, after in cmd_changes]


def rollback(v, keep, enabled, restore_files, cmd_restore, restart=True):
    ok = True
    if restore_files:
        log("rolling back to the backups in %s" % keep)
        rc, out = v.root("cp -p %s/snmpdv3.conf.bak %s && cp -p %s/rc.tcpip.bak %s"
                         % (keep, CONF, keep, RC_TCPIP))
        if rc != 0:
            log("ROLLBACK FAILED: %s" % out.strip()[-400:])
            log("restore by hand: cp -p %s/snmpdv3.conf.bak %s" % (keep, CONF))
            ok = False
    if cmd_restore:
        log("restoring the previous ODM cmdargs: %s"
            % ", ".join("%s %s" % (s, b or "(none)") for s, b in cmd_restore))
        try:
            chssys_set(v, dict(cmd_restore))
        except V.Abort as e:
            log("rollback of the ODM cmdargs failed: %s" % e)
            ok = False
    if restart and ok:
        try:
            run_services(v, enabled, stop=True)
        except V.Abort as e:
            log("rollback restart failed: %s" % e)
            ok = False
    return ok


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", required=True, help="VIOS host name or address")
    ap.add_argument("--user", default="padmin", help="ssh user (default padmin)")
    ap.add_argument("--ssh-opt", action="append", default=[], metavar="OPT", help="extra ssh option")
    ap.add_argument("--community", help="community name to configure; omit for recon only")
    ap.add_argument("--manager", action="append", default=[], metavar="IP[/BITS]",
                    help="permitted source address (repeatable); default any source")
    ap.add_argument("--v3-mibs", choices=("included", "excluded"), default="included",
                    help="snmpModules view (default included)")
    ap.add_argument("--aix-mibs", choices=("included", "excluded"), default="included",
                    help="aixmibd subtree 1.3.6.1.4.1.2.6.191 (default included)")
    ap.add_argument("--enable", action="append", default=list(S.SUBSYSTEMS), metavar="SUBSYS",
                    help="subsystems to run at boot (default all four)")
    ap.add_argument("--no-traps", action="store_true", help="comment out NOTIFY/TARGET_* instead of reporting them")
    ap.add_argument("--apply", action="store_true", help="write the files and (re)start the daemons")
    ap.add_argument("--no-restart", action="store_true", help="write the files and the ODM but leave the daemons alone")
    ap.add_argument("--json", action="store_true", help="machine-readable report")
    ap.add_argument("--print-config", action="store_true", help="print the files that would be written")
    args = ap.parse_args(argv)

    if args.community is not None and not args.community.strip():
        raise SystemExit("--community must not be empty")
    for opt in ("enable",):
        bad = [s for s in args.enable if s not in S.SUBSYSTEMS]
        if bad:
            raise SystemExit("unknown subsystem(s): %s" % ", ".join(bad))
    if args.apply and not args.community:
        raise SystemExit("--apply needs --community")

    started = time.time()
    try:
        v = V.Vios(args.host, args.user, args.ssh_opt)
        (p, enabled, conf_new, conf_changes, rc_new, rc_changes,
         cmdargs, cmd_changes) = build(v, args)
        report = {"host": args.host, "level": p["level"], "agent": p["agent"],
                  "services": p["services"], "boot": S.rc_autostart(p["rc_tcpip"]),
                  "cmdargs": p["cmdargs"],
                  # Findings describe the file as it will be after the plan: a
                  # TARGET_PARAMETERS naming a community that is no longer
                  # defined only matters once the new COMMUNITY lines are in.
                  "findings": S.findings(conf_new),
                  "changes": [{"file": c.path, "line": c.line, "why": c.why,
                               "before": c.before, "after": c.after}
                              for c in conf_changes + rc_changes],
                  "cmdargs_changes": [{"subsystem": s, "before": b, "after": a,
                                       "command": S.chssys_command(s, a)}
                                      for s, b, a in cmd_changes],
                  "verify": [], "ok": True}
        drift = bool(conf_changes or rc_changes or cmd_changes)

        if not args.json:
            show_probe(p, args.host, args)
            for f in report["findings"]:
                print("  %-10s %s" % ("finding", f))

        if not args.community:                      # recon only
            if not args.json:
                print("\nrecon only: pass --community to plan a configuration")
            else:
                print(json.dumps(report, indent=2))
            return 0

        if not args.json:
            if conf_changes:
                show_changes(CONF, conf_changes)
            if rc_changes:
                show_changes(RC_TCPIP, rc_changes)
            if cmd_changes:
                show_cmdargs(cmd_changes)
            if args.print_config:
                print("\n--- %s ---\n%s\n--- %s ---\n%s" % (CONF, conf_new, RC_TCPIP, rc_new))
            if not drift:
                print("\nconfiguration already matches the plan")
            else:
                print("\nplan: %d change(s) in %s, %d in %s, %d SRC cmdargs; daemons would be %s"
                      % (len(conf_changes), CONF, len(rc_changes), RC_TCPIP, len(cmd_changes),
                         "restarted" if drift else "left running"))
            if not args.manager:
                print("note: no --manager given, so any source address may poll (0.0.0.0 0.0.0.0)")

        if not args.apply:
            if args.json:
                print(json.dumps(report, indent=2))
            return 10 if drift else 0

        # Nothing to write means no backup, no upload, no restart of a healthy
        # agent; only a real change justifies touching anything at all.
        keep = None
        cmd_restore = []
        restore_files = bool(conf_changes or rc_changes)
        if drift:
            if not args.json:
                print("\napplying to %s ..." % args.host)
            try:
                if restore_files:
                    keep = backup(v)
                    install_files(v, conf_new, rc_new)
                # The ODM before the restart: startsrc reads it at start time.
                cmd_restore = apply_cmdargs(v, cmd_changes)
                if cmd_changes and not args.json:
                    print("  SRC cmdargs set with chssys: %s"
                          % ", ".join("%s '%s'" % (s, a) for s, b, a in cmd_changes))
            except Exception:
                rollback(v, keep, enabled, restore_files, cmd_restore, restart=False)
                raise
            if not args.no_restart:
                run_services(v, enabled, stop=True)
        elif not args.no_restart:
            run_services(v, enabled)                  # in sync: just start what is down

        if args.no_restart:
            if not args.json:
                print("\napplied to %s; daemons left alone (--no-restart)" % args.host)
        else:
            results = verify(v, args.community, enabled, cmdargs)
            report["verify"] = results
            failed = [r for r in results if not r["ok"]]
            if failed:
                report["ok"] = False
                if not args.json:
                    for r in failed:
                        print("  FAIL %s: %s\n       %s" % (r["check"], r["command"], r["output"]))
                if drift:
                    rollback(v, keep, enabled, restore_files, cmd_restore)
                    log("verification failed: configuration rolled back")
                else:
                    log("verification failed: the configuration was already in sync, nothing to roll back")
                if args.json:
                    print(json.dumps(report, indent=2))
                return 1
            if not args.json:
                for r in results:
                    print("  ok   %s" % r["check"])
                print("\napplied and verified in %.1fs" % (time.time() - started))

        if args.json:
            print(json.dumps(report, indent=2))
        return 0
    except V.Abort as e:
        if args.json:
            print(json.dumps({"host": args.host, "ok": False, "error": str(e)}, indent=2))
        log("error: %s" % e)
        return e.code
    except Exception as e:                         # one broken host must not look like a success
        if args.json:
            print(json.dumps({"host": args.host, "ok": False, "error": "%s: %s" % (type(e).__name__, e)}, indent=2))
        log("error: %s: %s" % (type(e).__name__, e))
        return 1


if __name__ == "__main__":
    sys.exit(main())
