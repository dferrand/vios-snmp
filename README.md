# vios-snmp

Configure the **SNMPv1 agent** on a PowerVM VIOS from a Linux box: `/etc/snmpdv3.conf`,
`/etc/rc.tcpip`, the SRC subsystem objects the subagents read their community from, the
four daemons, and then prove it with `snmpinfo`.

Traps are out of scope. `NOTIFY`, `TARGET_ADDRESS` and `TARGET_PARAMETERS` are reported
and left alone; `--no-traps` comments them out if you really want that.

## Why `snmpdv3.conf` for SNMPv1

`/usr/sbin/snmpd` is a symlink to `snmpdv3ne` on VIOS, and that agent serves SNMPv1, v2c
and v3 from the same file. Two things make SNMPv1 work:

* a `COMMUNITY` line — the community name, and the address/mask allowed to use it;
* a `VACM_GROUP ... SNMPv1 <name>` whose security-name matches that community.

The factory file ships both commented out (`#COMMUNITY public ...`, group `public`), plus
`DEFAULT_SECURITY no-access`, so out of the box the agent answers nobody. That is what this
tool fixes.

## Usage

```sh
# recon only: read the VIOS, change nothing
./vios_snmp.py --host vios1

# plan: print the diff, write nothing (exit 10 when there is drift)
./vios_snmp.py --host vios1 --community 'CHANGEME'

# test: the snmpinfo checks only, read-only (exit 1 when a check fails)
./vios_snmp.py --host vios1 --test
./vios_snmp.py --host vios1 --test --community 'CHANGEME'

# restart: bounce the four daemons in order and check them, write nothing
./vios_snmp.py --host vios1 --restart

# reset-boots: the agent initialised from an address this host no longer has
./vios_snmp.py --host vios1 --reset-boots

# apply: back up, write, restart the daemons, verify with snmpinfo, roll back on failure
./vios_snmp.py --host vios1 --community 'CHANGEME' --apply

# restrict polling to the NOC instead of any source
./vios_snmp.py --host vios1 --community 'CHANGEME' --manager 10.20.0.10 --manager 10.30.0.0/24 --apply
```

Exit codes: `0` in sync (or applied and verified, or every check passed), `10` drift found
in plan mode, `1` error or a failed check.

Other flags: `--restart` (bounce and verify), `--reset-boots` (rebuild the agent's boots
file), `--no-restart` (write only), `--no-traps`,
`--v3-mibs excluded`,
`--aix-mibs excluded`, `--enable SUBSYS` (repeatable; default all four), `--print-config`,
`--json`, `--user`, `--ssh-opt`.

## Testing a host with snmpinfo

`--test` runs the same checks `--apply` ends with, and writes nothing: no backup, no upload,
no `chssys`, no restart. It is the mode for a host you are only allowed to look at, and for a
cron job watching an agent that should keep answering.

With no `--community` it tests the community the host is configured for — the first active
`COMMUNITY` line, else `public` — so `--host vios1 --test` works as-is on a configured VIOS.

| check | command | proves |
|---|---|---|
| `agent` | `ls -l /usr/sbin/snmpd` | the link resolves to `snmpdv3ne` (or `snmpdv3e`), the only agents that read `/etc/snmpdv3.conf` |
| `cmdargs` | `odmget -q subsysname=<sub> SRCsubsys`, `ps -ef \| grep mibd` | the ODM and the running subagents carry `-c <community>` |
| `system` | `snmpinfo -m get -c <c> 1.3.6.1.2.1.1.1.0` | the master answers on 161 (`sysDescr`) |
| `snmpmibd` | `snmpinfo -m get -c <c> 1.3.6.1.2.1.2.1.0` | the MIB-II child answers (`ifNumber`), i.e. DPI2 registration works at all |
| `aixmibd` | `snmpinfo -m get -c <c> 1.3.6.1.4.1.2.6.191.2.4.1.0` | aixmibd serves `aixPageThreshold` |
| `hostmibd` | `snmpinfo -m get -c <c> 1.3.6.1.2.1.25.1.1.0` | hostmibd serves `hrSystemUptime` |

AIX links it relatively (`snmpd -> snmpdv3ne`), so the target is resolved against
`/usr/sbin` and compared as a path, not as text. `snmpdv3e` — the encrypted agent — passes
with a note that it needs the `snmp.crypto` fileset installed.

`snmpv3_ssw` on VIOS 4.1 / AIX 7 takes `-e`, `-n` and `-1` only (there is no `-l`), so the
current mode is read from the link itself rather than asked of the switch.

Any other target is a plan item, repaired the supported way rather than by hand:

```
agent link  (1 change)
  /usr/sbin/snmpd -> /usr/sbin/snmpdv1
    snmpv3_ssw -n   (switches it to /usr/sbin/snmpdv3ne)
```

`--restart` takes `--enable` too: with `snmpd` left out of the list it bounces exactly those
children and leaves the master (and every other subtree) alone — the cure for one child that
is not registered. `--restart` with no `--enable` is the cure for a wholesale stale
registration: DPI2 children bind to the master that was
running when they started, so a master that was replaced (by an agent switch, for instance)
leaves them answering nothing while `lssrc` still says active. It stops the three subagents,
then `snmpd`, and starts them back in the opposite order, then runs the same checks — and
writes nothing at all. The `--test` failure for that case says so in a `hint:` line.

`--apply` runs `snmpv3_ssw -n` first — before the files and before the daemons come back —
then re-reads the link and aborts if it still points elsewhere. `--test` never switches it;
it just fails the `agent` check. If verification then fails, a rollback switches the link
back with the matching flag (`-1` for `snmpdv1`, `-e` for `snmpdv3e`); a target `snmpv3_ssw`
cannot select (a hand-made link to something else) is left at `snmpdv3ne`, and the rollback
says so.

Each check carries several forms and uses the first one that answers, because this `snmpinfo`
is quirky by level. Its modes are `get|next|set|dump` — **there is no `walk`**. `-m get` on a
numeric instance needs no MIB file and cannot be misread, so it goes first; `-m dump` (IBM's
form, `-md`) prints the readable subtree but resolves the name through the client's MIB files,
so on a VIOS without them it answers nothing at all rather than failing. `--json` shows which
form answered — a host that only dumps is visible instead of silently passing.

A subagent that fails while its `cmdargs` check passed carries a `hint:` line, because the
credential is not the problem. Which hint depends on what answered: `noSuchName` from the
master with another child answering means *this* child is not registered (bounce just it and
look at `/var/tmp/snmpd.log`); no child answering at all points at the master, so bounce the
four daemons in order.

Exit `0` when every check passes, `1` when any fails, with the failing command and what came
back printed (`(no output: nothing came back)` when the agent answered with nothing at all).
`snmpinfo` can exit 0 while printing an error, so the output is checked for `0821-103`,
`No response`, `Timeout` and `noSuchName`/`noSuchObject` as well as the exit code. The aixMIB
check accepts the subtree OID as well as the `aixPageThreshold` symbol, because `snmpinfo`
prints numeric OIDs when it cannot resolve the MIB name (VIOS 4.1 does).

## What it changes

**`/etc/snmpdv3.conf`** — five lines on a factory file, in place, never a regeneration:

| line | change |
|---|---|
| `VACM_GROUP group1 SNMPv1 public -` | security-name becomes the community |
| `#VACM_VIEW defaultView internet ...` | un-commented, `included` |
| `VACM_VIEW defaultView snmpModules ... excluded` | `included` |
| `VACM_VIEW defaultView 1.3.6.1.4.1.2.6.191 ... excluded` | `included` (aixmibd's subtree) |
| `#COMMUNITY public public ...` | active `COMMUNITY <name> <name> noAuthNoPriv <addr> <mask> -` |

Everything else — the IBM prologue, the directive documentation, `VACM_ACCESS`,
`DEFAULT_SECURITY`, `logging`, `smux`, the trap directives — stays byte-identical. The
header comment block is verified untouched by a test. Extra active `COMMUNITY` lines not in
the plan are commented out, not deleted.

**`/etc/rc.tcpip`** — the four start lines are un-commented, and nothing else:

```
start /usr/sbin/snmpd "$src_running"
start /usr/sbin/snmpmibd "$src_running"
start /usr/sbin/hostmibd "$src_running"
start /usr/sbin/aixmibd "$src_running"
```

The community is **not** written here. `rc.tcpip` starts a daemon with
`startsrc -s <cmd> -a "$3"`, and `startsrc` *appends* `-a` to the cmdargs stored in the
ODM, so an empty third argument leaves the stored value in force. A start line that
still carries `"-c <old>"` is rewritten plain, which is drift repair, not drift.
`dpid2` is left as the vendor shipped it.

**The SRC subsystem objects** — the subagents' community, set with `chssys`
([IBM technote 884646](https://www.ibm.com/support/pages/node/884646)):

```
chssys -s snmpmibd -a "-c <community>"
chssys -s hostmibd -a "-c <community>"
chssys -s aixmibd  -a "-c <community>"
```

`snmpmibd`, `hostmibd` and `aixmibd` take their community as `-c <name>` on their own
command line, and the ODM is the supported place to store it: one value then serves the
manual `startsrc` and the reboot alike. An empty `-a` clears it, which means `public` —
that is how `--community public` undoes a previous run. `snmpd` takes its community
from `snmpdv3.conf` and is never `chssys`'d.

## Apply sequence

1. `cp -p` backups next to the files (`<file>.bak.<timestamp>`) and into
   `/home/padmin/.vios_snmp-<timestamp>/`.
2. Upload both files to padmin's home, `cp` them into `/etc` as root (overwriting the inode
   keeps `root:system` and `644`), remove the staged copies.
3. Read both files back and compare — `cp` exiting 0 is not proof the bytes landed.
4. `chssys` each subagent whose stored cmdargs differ, then read the value back with
   `odmget -q subsysname=<sub> SRCsubsys` — `chssys` exiting 0 is not proof the ODM holds
   the value either. `odmget` names the attribute, so the read cannot be shifted by the
   value itself the way a colon-separated `lssrc -Ss` row can.
5. Stop the subagents, then `snmpd`; start `snmpd`, then the subagents with a plain
   `startsrc -s <sub>`, which picks up the cmdargs just written.
6. Checks: the ODM cmdargs, `ps -ef | grep mibd` showing `-c <community>` on each running
   subagent (the ODM alone says what the *next* start will use), then
   `snmpinfo -md -v -c <community> system`, plus `aixpagingspace` and the host-resources
   subtree when those subagents are enabled.
7. Any failed check → restore the backups, `chssys` the previous cmdargs back, restart,
   exit 1.

A second apply on an unchanged VIOS issues no writes, no `chssys` and no
`stopsrc`/`startsrc`: the diff is empty, so there is nothing to do. That is tested, as is
a host whose files are already right and whose ODM is not.

## Reading the header

```
  agent      /usr/sbin/snmpdv3ne
  services   snmpd active, snmpmibd active, hostmibd active, aixmibd active
  dpid2      inoperative
  agent ip   172.16.7.154
  v1 conf    -rw-r--r-- 1 root system 1180 Nov 18 2024 /etc/snmpd.conf snmpd 172.16.7.154 public read
  snmp pkg   bos.net.tcp.client 7.2.4.8
  local ips  10.17.10.21, 172.16.7.154
  host       vios21 -> 172.16.7.154 (from /etc/hosts)
  listen     tcp4 0 0 *.161 *.* LISTEN udp4 0 0 *.161 *.*
  running    20316534 /usr/sbin/snmpdv3ne since 13:44:26
```

`agent ip` is the address the agent says it initialised from, out of its own log
(`/var/tmp/snmpdv3.log`, `Agent using IP address UDP …`); `local ips` is what `ifconfig -a`
reports. They are printed side by side and never compared: on a VIOS the address clients poll is
often **NAT'd** while the agent's own is the real interface address, so a difference means
nothing.

`v1 conf` appears only when `/etc/snmpd.conf` exists — a leftover v1 configuration is invisible in
every other view, and a stale community in it is one of the few things that can matter to a
daemon other than the one this tool configures. `snmp pkg` is the `bos.net.tcp.client` level,
which is what the agent and the MIB daemons all come from.

`host` is the local hostname and what `/etc/hosts` says it is. A DPI2 child reaches the master
**by name**, so a name that resolves to an address this host does not have (`local ips`) is the
classic reason a child logs `1473-665 Connect to SNMP agent failed` while outside clients poll
the box happily.

`--reset-boots` is for a genuinely stale `/etc/snmpd.boots` (the log says `Using existing file
/etc/snmpd.boots`, and the address in it is gone after a network change): it moves the file to
`/etc/snmpd.boots.bak.<timestamp>` — never deleted, because a v3 user's localized keys would
have to be recovered from it — and restarts the four daemons in order so the agent rebuilds it.

`listen` comes from `netstat -an` (`-a` matters: without it AIX lists only connected sockets,
never the listening one), and `running` resolves the live process through
`/proc/<pid>/object/a.out` — `ps` shows `argv[0]`, i.e. `/usr/sbin/snmpd`, whatever the link
says, so it cannot tell you which agent is actually running.

Those two lines are what a child's `1473-665 Connect to SNMP agent failed` is about: the agent
has to be listening on a socket the child can reach, and the process has to be the agent the
link points at.

## Report-only findings

Recon and `--test` report whether `host loopback` on the VIOS returns `127.0.0.1`.
If it does not, check the IPv4 loopback aliases in `/etc/hosts` and the resolver
order before restarting SNMP subagents. The tool never changes `/etc/hosts`;
this finding does not override the SNMP test results or change plan drift.

Each run prints what it noticed but did not change: trap directives left in place, a
`TARGET_PARAMETERS` that still names a community no `COMMUNITY` line defines (its v1 traps
will fail silently after a community change), `DEFAULT_SECURITY`, `USM_USER` entries, and
`inet0 bootup_option` when it is not `no` (rc.tcpip then skips the SRC start path). Recon
also prints `mibd args`: the community currently stored in the ODM for the three
subagents, `(none)` meaning they answer `public`.

## Layout

```
vios_snmp.py            CLI: probe, plan, apply, verify, rollback
vioslib/snmpconf.py     pure functions: parse / render / diff both files, build the chssys plan
vioslib/vios.py         ssh/scp to the VIOS: run() as padmin, root() via oem_setup_env
tests/test_snmpconf.py  the file edits and the chssys plan, against the real factory files
tests/test_vios_snmp.py CLI end to end against a fake VIOS (files and ODM in memory)
```

## Tests

```sh
python3 -m unittest discover -s tests -v
```

`tests/fixtures/` holds the factory `snmpdv3.conf`, the hand-made configuration from the lab
VIOS and the stock `rc.tcpip`. The golden test asserts the rendered file is functionally
identical to the hand-made one (same active directives, order-independent), and that only
the five expected lines moved.

## Not covered

* SNMPv3 users, engine-ID handling, `pwtokey`.
* Trap destinations.
* Anything on the network side (firewall rules, allowed ports).
* Only exercised against a fake VIOS so far — the first real run should be `--host <vios>`
  with no `--community`, which is read-only.
