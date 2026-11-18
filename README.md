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

# apply: back up, write, restart the daemons, verify with snmpinfo, roll back on failure
./vios_snmp.py --host vios1 --community 'CHANGEME' --apply

# restrict polling to the NOC instead of any source
./vios_snmp.py --host vios1 --community 'CHANGEME' --manager 10.20.0.10 --manager 10.30.0.0/24 --apply
```

Exit codes: `0` in sync (or applied and verified, or every check passed), `10` drift found
in plan mode, `1` error or a failed check.

Other flags: `--no-restart` (write only), `--no-traps`, `--v3-mibs excluded`,
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
| `cmdargs` | `lssrc -Ss <sub>`, `ps -ef \| grep mibd` | the ODM and the running subagents carry `-c <community>` |
| `system` | `snmpinfo -md -v -c <c> system` | the master answers on 161 (`sysDescr`) |
| `aixmibd` | `snmpinfo -md -c <c> aixpagingspace` | the aixMIB subtree is registered |
| `hostmibd` | `snmpinfo -md -c <c> 1.3.6.1.2.1.25.1.1.0` | host resources are registered |

Exit `0` when every check passes, `1` when any fails, with the failing command and what came
back printed. `snmpinfo` can exit 0 while printing an error, so the output is checked for
`0821-103`, `No response`, `Timeout` and `noSuchName`/`noSuchObject` as well as the exit code.

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
4. `chssys` each subagent whose stored cmdargs differ, then read them back with
   `lssrc -Ss` — `chssys` exiting 0 is not proof the ODM holds the value either.
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

## Report-only findings

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
