"""Line-surgical edits to /etc/snmpdv3.conf and /etc/rc.tcpip, plus the chssys plan.

The two files ship with long IBM comment blocks and are also edited by hand on
the VIO servers, so nothing here regenerates a file: each function rewrites only
the lines it owns, keeps them where they are, and leaves every other byte alone.
That is why the module is a parser plus a handful of targeted edits instead of a
template.

The subagents' community is not in either file: it is the `-c <name>` in the SRC
subsystem object, so the last section builds the chssys plan instead of a diff.

Statements in snmpdv3.conf are not order-dependent (the file says so in its own
header), so an entry may be appended at the end when there is no existing line to
rewrite; active directives can then be compared as an order-independent set,
which is what `active()` gives the verifier.

Every edit is returned as a Change record: the CLI prints them as a diff and
uses them to decide whether the daemons must be restarted.
"""

import ipaddress
import re
import shlex

CONF = "/etc/snmpdv3.conf"
RC_TCPIP = "/etc/rc.tcpip"
# Only the old v1 agent reads this; it is named so the report can say so.
CONF_V1 = "/etc/snmpd.conf"

# Upper-case directives, i.e. the ones this tool reasons about. The lower-case
# entries (logging, smux) are left untouched and are not modelled.
DIRECTIVES = ("USM_USER", "VACM_GROUP", "VACM_VIEW", "VACM_ACCESS", "NOTIFY",
              "TARGET_ADDRESS", "TARGET_PARAMETERS", "COMMUNITY", "DEFAULT_SECURITY")

TRAP_DIRECTIVES = ("NOTIFY", "TARGET_ADDRESS", "TARGET_PARAMETERS")

# snmpd is the agent; the three subagents serve the MIB-II, host-resources and
# aixMIB subtrees and are useless without it.
AGENT = "snmpd"
SUBAGENTS = ("snmpmibd", "hostmibd", "aixmibd")
SUBSYSTEMS = (AGENT,) + SUBAGENTS

ANY = "0.0.0.0"
ANY_MASK = "0.0.0.0"

AIX_SUBTREE = "1.3.6.1.4.1.2.6.191"   # aixmibd's enterprise subtree
V3_SUBTREE = "snmpModules"            # USM/MIB objects, irrelevant to SNMPv1

# field positions inside the entries we rewrite
F_GROUP_NAME, F_GROUP_MODEL, F_GROUP_SECNAME = 0, 1, 2
F_VIEW_NAME, F_VIEW_SUBTREE, F_VIEW_MASK, F_VIEW_TYPE = 0, 1, 2, 3
F_TP_NAME, F_TP_SECNAME = 0, 3


def _align(old, new):
    """Reuse the original line's column spacing when the field count matches.

    IBM's file is column-aligned and admins keep it that way, so a rewritten line
    that keeps its columns makes the diff readable and the file look native.
    """
    body = old.lstrip("#* \t").strip()
    toks = re.split(r"\s+", body)
    seps = re.findall(r"\s+", body)
    ntoks = new.split()
    if len(toks) != len(ntoks) or len(seps) < len(ntoks) - 1:
        return new
    out = ntoks[0]
    for i, tok in enumerate(ntoks[1:]):
        out += seps[i] + tok
    return out


class Change(object):
    """One line that the plan would rewrite, with the reason in plain words."""

    __slots__ = ("path", "line", "before", "after", "why")

    def __init__(self, path, line, before, after, why):
        self.path, self.line, self.before, self.after, self.why = path, line, before, after, why

    def __repr__(self):
        return "Change(%s:%d %s)" % (self.path, self.line, self.why)

    def diff(self):
        out = []
        if self.before:
            out.append("- %s" % self.before)
        if self.after:
            out.append("+ %s" % self.after)
        return "\n".join(out)


class Conf(object):
    """A configuration file held as lines, plus the edits made to it."""

    def __init__(self, text, name=CONF):
        self.name = name
        self.eol = "\n" if text.endswith("\n") else ""
        self.lines = text.splitlines()
        self.changes = []

    def text(self):
        return "\n".join(self.lines) + self.eol

    # ---------------------------------------------------------------- scanning

    def entries(self, directive=None):
        """Active entries as (index, directive, fields). A comment starts in column 1."""
        out = []
        for i, line in enumerate(self.lines):
            if not line or line[0] in "#*":
                continue
            tok = line.split()
            if not tok or tok[0] not in DIRECTIVES:
                continue
            if directive and tok[0] != directive:
                continue
            out.append((i, tok[0], tok[1:]))
        return out

    def commented(self, directive):
        """Commented-out entries as (index, directive, fields), e.g. the factory '#COMMUNITY public ...'."""
        out = []
        for i, line in enumerate(self.lines):
            if not line or line[0] not in "#*":
                continue
            tok = line.lstrip("#*").split()
            if tok and tok[0] == directive:
                out.append((i, tok[0], tok[1:]))
        return out

    # ----------------------------------------------------------------- editing

    def replace(self, i, new, why):
        old = self.lines[i]
        new = _align(old, new)
        if old == new:
            return False
        self.lines[i] = new
        self.changes.append(Change(self.name, i + 1, old, new, why))
        return True

    def append(self, new, why):
        self.lines.append(new)
        self.changes.append(Change(self.name, len(self.lines), "", new, why))
        return True


# --------------------------------------------------------------------- render

def community_entry(name, addr=ANY, mask=ANY_MASK):
    """COMMUNITY communityName securityName securityLevel netAddr netMask storageType"""
    return "COMMUNITY %s %s noAuthNoPriv %s %s -" % (name, name, addr, mask)


def group_entry(group, name):
    """VACM_GROUP groupName securityModel securityName storageType"""
    return "VACM_GROUP %s SNMPv1 %s -" % (group, name)


def view_entry(name, subtree, vtype):
    """VACM_VIEW viewName viewSubtree viewMask viewType storageType"""
    return "VACM_VIEW %s %s - %s -" % (name, subtree, vtype)


def normalize_manager(spec):
    """'10.20.0.10' -> (10.20.0.10, 255.255.255.255); '10.20.0.0/24' -> (10.20.0.0, 255.255.255.0)."""
    spec = spec.strip()
    if "/" not in spec:
        return spec, "255.255.255.255"
    addr, bits = spec.split("/", 1)
    bits = int(bits)
    if not 0 <= bits <= 32:
        raise ValueError("bad prefix length in %r" % spec)
    mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF if bits else 0
    return addr, "%d.%d.%d.%d" % ((mask >> 24) & 0xFF, (mask >> 16) & 0xFF, (mask >> 8) & 0xFF, mask & 0xFF)


# ------------------------------------------------------------------ snmpdv3

def _set_group(c, community):
    groups = [e for e in c.entries("VACM_GROUP")
              if len(e[2]) > F_GROUP_MODEL and e[2][F_GROUP_MODEL].lower() == "snmpv1"]
    if not groups:
        c.append(group_entry("group1", community), "no SNMPv1 group existed: create group1")
        return
    for i, _, f in groups:
        name = f[F_GROUP_NAME] if f else "group1"
        c.replace(i, group_entry(name, community), "community name the SNMPv1 group security-name refers to")


def _set_communities(c, community, managers):
    """The tool owns every active COMMUNITY line: they all become <community> for the planned sources."""
    active = [e[0] for e in c.entries("COMMUNITY")]
    anchors = active or [e[0] for e in c.commented("COMMUNITY") if len(e[2]) >= 5][:1]
    for k, (addr, mask) in enumerate(managers):
        line = community_entry(community, addr, mask)
        if k < len(anchors):
            c.replace(anchors[k], line, "community, source address and source mask")
        else:
            # Appending is safe: the file's own header states entries are order-independent.
            c.append(line, "additional permitted source address")
    for extra in anchors[len(managers):]:
        c.replace(extra, "# " + c.lines[extra], "community not in the plan, disabled")


def _set_view(c, subtree, vtype, why):
    views = [e for e in c.entries("VACM_VIEW")
             if len(e[2]) > F_VIEW_SUBTREE and e[2][F_VIEW_SUBTREE] == subtree]
    if views:
        for i, _, f in views:
            if len(f) > F_VIEW_TYPE and f[F_VIEW_TYPE] != vtype:
                c.replace(i, view_entry(f[F_VIEW_NAME], subtree, vtype), why)
        return
    hidden = [e for e in c.commented("VACM_VIEW")
              if len(e[2]) > F_VIEW_SUBTREE and e[2][F_VIEW_SUBTREE] == subtree]
    if hidden:
        i, _, f = hidden[0]
        c.replace(i, view_entry(f[F_VIEW_NAME], subtree, vtype), why + " (was commented out)")
        return
    c.append(view_entry("defaultView", subtree, vtype), why)


def _comment_traps(c):
    for i, d, _ in c.entries():
        if d in TRAP_DIRECTIVES:
            c.replace(i, "# " + c.lines[i], "trap configuration disabled (--no-traps)")


def conf_desired(text, community=None, managers=None, v3_mibs="included",
                 aix_mibs="included", no_traps=False, name=CONF):
    """Return (new_text, changes) for /etc/snmpdv3.conf.

    `managers` is a list of (address, mask) pairs; no entry means any source,
    which is what the factory file and IBM's own community example use.
    """
    c = Conf(text, name)
    if community:
        _set_group(c, community)
        _set_communities(c, community, managers or [(ANY, ANY_MASK)])
        _set_view(c, "internet", "included", "the default view must allow the whole tree")
        _set_view(c, AIX_SUBTREE, aix_mibs, "aixmibd subtree, excluded by the factory file")
        _set_view(c, V3_SUBTREE, v3_mibs, "snmpModules subtree (MIB/USM objects)")
    if no_traps:
        _comment_traps(c)
    return c.text(), c.changes


def active_communities(text):
    """Community names that an active COMMUNITY line defines, in file order."""
    return [f[0] for i, d, f in Conf(text).entries("COMMUNITY") if f]


def findings(text):
    """Facts about the current file that the plan must report but not change."""
    c = Conf(text)
    out = []
    old = [f[F_TP_SECNAME] for i, d, f in c.entries("TARGET_PARAMETERS") if len(f) > F_TP_SECNAME]
    comm = [f[0] for i, d, f in c.entries("COMMUNITY") if f]
    traps = [d for i, d, _ in c.entries() if d in TRAP_DIRECTIVES]
    if traps:
        out.append("%d trap directive(s) left untouched (%s)" % (len(traps), ", ".join(sorted(set(traps)))))
    # With no active COMMUNITY at all, every TARGET_PARAMETERS name is undefined.
    stale = sorted(set(n for n in old if n not in comm))
    if stale:
        out.append("TARGET_PARAMETERS still names community %s, which no COMMUNITY line defines: "
                   "v1 traps will be sent under that name" % ", ".join(stale))
    for i, d, f in c.entries("DEFAULT_SECURITY"):
        out.append("DEFAULT_SECURITY %s" % " ".join(f))
    if not comm:
        out.append("no active COMMUNITY line: the agent answers nobody")
    for i, d, f in c.entries("USM_USER"):
        out.append("USM_USER %s present (SNMPv3 is out of scope here)" % (f[0] if f else "?"))
    return out


def trap_entries(text):
    """Active trap directives as (index, line) — reported, never changed unless asked."""
    c = Conf(text)
    return [(i, c.lines[i]) for i, d, _ in c.entries() if d in TRAP_DIRECTIVES]


def active(text):
    """Active directives as an order-independent sorted list — how two files are proven equivalent."""
    c = Conf(text)
    return sorted([tuple([d] + f) for _, d, f in c.entries()])


# ------------------------------------------------------------------- rc.tcpip

def _start_re(subs):
    return re.compile(r"^#?\s*start\s+/usr/sbin/(%s)(?=\s|$)" % "|".join(subs))


def _find_start(lines, subs, name):
    rx = _start_re(subs)
    for i, line in enumerate(lines):
        if line.startswith("#!"):      # the shebang also matches nothing, but be explicit
            continue
        m = rx.match(line)
        if m and m.group(1) == name:
            return i
    return None


def hosts_desired(text):
    """Add the alias only if there is one unambiguous IPv4 loopback row."""
    rows = text.splitlines(keepends=True)
    candidates = []
    for i, row in enumerate(rows):
        body, _, _ = row.partition("#")
        fields = body.split()
        if not fields:
            continue
        if any(name.lower().rstrip(".") == "loopback" for name in fields[1:]):
            try:
                ipv6_loopback = ipaddress.ip_address(fields[0]) == ipaddress.IPv6Address("::1")
            except ValueError:
                ipv6_loopback = False
            # An IPv6 loopback alias can coexist with the IPv4 alias. Leave
            # that row intact, but refuse other mappings or an existing alias.
            if not ipv6_loopback:
                return text, []
        if fields[0] == "127.0.0.1":
            candidates.append((i, len(body.rstrip())))
    if len(candidates) != 1:
        return text, []
    i, end = candidates[0]
    before = rows[i]
    tail = before[end:]
    rows[i] = before[:end] + " loopback" + (" " if tail.startswith("#") else "") + tail
    return "".join(rows), [Change("/etc/hosts", i + 1, before.rstrip("\r\n"),
                                  rows[i].rstrip("\r\n"), "add the IPv4 loopback alias")]


def rc_desired(text, enabled=SUBSYSTEMS, name=RC_TCPIP):
    """Return (new_text, changes) for /etc/rc.tcpip.

    Only the start lines are owned here: which daemons come up at boot. The
    subagents' community is *not* written into this file. rc.tcpip starts them
    with `startsrc -s <cmd> -a "$3"` and startsrc appends -a to the ODM cmdargs,
    so an empty third argument leaves the chssys value in force. IBM technote
    884646 puts the community in the ODM for exactly this reason.
    """
    c = Conf(text, name)
    for sub in SUBSYSTEMS:
        want = sub in enabled
        line = 'start /usr/sbin/%s "$src_running"' % sub
        i = _find_start(c.lines, SUBSYSTEMS, sub)
        if i is None:
            if want:
                at = next((n for n, l in enumerate(c.lines) if "Wait for srcmstr" in l), len(c.lines))
                c.lines.insert(at, line)
                c.changes.append(Change(name, at + 1, "", line, "no start line existed: add it"))
            continue
        if want:
            c.replace(i, line, "start at boot")
        else:
            # Exactly one leading #, so disabling twice is a no-op.
            c.replace(i, "#" + c.lines[i].lstrip("#").lstrip(), "not started at boot")
    return c.text(), c.changes


def rc_autostart(text):
    """Which of the four subsystems rc.tcpip would start: {name: bool}."""
    out = {}
    for sub in SUBSYSTEMS:
        i = _find_start(text.splitlines(), SUBSYSTEMS, sub)
        out[sub] = bool(i is not None and not text.splitlines()[i].lstrip().startswith("#"))
    return out


# ------------------------------------------------------------- SRC cmdargs
#
# The three DPI2 subagents take their community as `-c <name>` on the command
# line. That argument belongs in the SRC subsystem object (ODM), set with
# chssys, not in rc.tcpip: rc.tcpip starts them with `startsrc -s <cmd> -a "$3"`
# and startsrc *appends* -a to the cmdargs from the ODM, so a plain start line
# leaves the chssys value in force. IBM technote 884646 does it this way.
#
# Read the value back with odmget, not with lssrc -Ss: odmget prints the stanza
# as `attribute = "value"` lines, so the value arrives quoted and intact, while
# lssrc renders a colon-separated row whose third field shifts as soon as the
# cmdargs contain a colon. lssrc stays as the fallback for a host where the
# odmget read comes back empty.
#
# An empty cmdargs means "use public", which is also how the technote undoes
# the change (`chssys -s aixmibd -a ""`).

ODM_QUERY = "odmget -q subsysname=%s SRCsubsys"


def cmdargs_desired(community, enabled=SUBSYSTEMS):
    """{subsystem: cmdargs} for the subagents; snmpd takes its community from snmpdv3.conf."""
    out = {}
    for sub in SUBAGENTS:
        if sub in enabled and community and community != "public":
            out[sub] = "-c " + community
        else:
            out[sub] = ""
    return out


def cmdargs_from_odm(text):
    """cmdargs from `odmget -q subsysname=<sub> SRCsubsys`; None when the stanza has none.

    odmget prints one `attribute = "value"` line per field, so the value arrives
    quoted and intact — that is why it is the source of truth here.
    """
    found = None
    for line in text.splitlines():
        s = line.strip()
        if " = " not in s:
            continue
        key, value = [p.strip() for p in s.split(" = ", 1)]
        if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        if key == "cmdargs":
            found = value
    return found


def cmdargs_from_lssrc(text):
    """cmdargs from one `lssrc -Ss <sub>` row: the third colon-separated field.

    The row is `subsysname:synonym:cmdargs:path:...`; the header line starts with
    '#' and is skipped. Fallback only: a colon inside the cmdargs shifts the fields.
    """
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) >= 3:
            return fields[2].strip().strip("\"'")
    return ""


def cmdargs_norm(args):
    """Comparison form: whitespace collapsed and wrapping quotes dropped.

    The ODM keeps whatever chssys was given, so a value that differs only in
    spacing is the same value. Comparing raw text makes the tool rewrite it on
    every run.
    """
    s = (args or "").strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        s = s[1:-1]
    return " ".join(s.split())


def cmdargs_changes(current, desired):
    """[(subsystem, before, after)] for the subagents whose cmdargs really differ."""
    out = []
    for sub in sorted(desired):
        before = (current.get(sub) or "").strip()
        if cmdargs_norm(before) != cmdargs_norm(desired[sub]):
            out.append((sub, before, desired[sub]))
    return out


def chssys_command(sub, cmdargs):
    """A chssys line; empty cmdargs clears the ODM value, which means public."""
    return "chssys -s %s -a %s" % (sub, shlex.quote(cmdargs))
