# vios-snmp

Configure the **SNMPv1 agent** on a PowerVM VIOS from a Linux box: `/etc/snmpdv3.conf`,
`/etc/rc.tcpip`, the four daemons, and then prove it with `snmpinfo`.

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

# apply: back up, write, restart the daemons, verify with snmpinfo, roll back on failure
./vios_snmp.py --host vios1 --community 'CHANGEME' --apply

# restrict polling to the NOC instead of any source
./vios_snmp.py --host vios1 --community 'CHANGEME' --manager 10.20.0.10 --manager 10.30.0.0/24 --apply
```

Exit codes: `0` in sync (or applied and verified), `10` drift found in plan mode, `1` error.

Other flags: `--no-restart` (write only), `--no-traps`, `--v3-mibs excluded`,
`--aix-mibs excluded`, `--enable SUBSYS` (repeatable; default all four), `--print-config`,
`--json`, `--user`, `--ssh-opt`.

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

**`/etc/rc.tcpip`** — the four start lines are un-commented:

```
start /usr/sbin/snmpd "$src_running"
start /usr/sbin/snmpmibd "$src_running" "-c <community>"
start /usr/sbin/hostmibd "$src_running" "-c <community>"
start /usr/sbin/aixmibd "$src_running" "-c <community>"
```

The subagents take the community as a command argument because `rc.tcpip` starts them with
`startsrc -s <cmd> -a "$3"`, so the ODM `cmdargs` do not apply and they would otherwise
answer `public`. `dpid2` is left as the vendor shipped it.

## Apply sequence

1. `cp -p` backups next to the files (`<file>.bak.<timestamp>`) and into
   `/home/padmin/.vios_snmp-<timestamp>/`.
2. Upload both files to padmin's home, `cp` them into `/etc` as root (overwriting the inode
   keeps `root:system` and `644`), remove the staged copies.
3. Read both files back and compare — `cp` exiting 0 is not proof the bytes landed.
4. Stop the subagents, then `snmpd`; start `snmpd`, then the subagents with `-c <community>`.
5. `snmpinfo -md -v -c <community> system`, plus `aixpagingspace` and the host-resources
   subtree when those subagents are enabled.
6. Any failed check → restore the backups, restart, exit 1.

A second apply on an unchanged VIOS issues no writes and no `stopsrc`/`startsrc`: the diff
is empty, so there is nothing to do. That is tested.

## Report-only findings

Each run prints what it noticed but did not change: trap directives left in place, a
`TARGET_PARAMETERS` that still names a community no `COMMUNITY` line defines (its v1 traps
will fail silently after a community change), `DEFAULT_SECURITY`, `USM_USER` entries, and
`inet0 bootup_option` when it is not `no` (rc.tcpip then skips the SRC start path).

## Layout

```
vios_snmp.py            CLI: probe, plan, apply, verify, rollback
vioslib/snmpconf.py     pure functions: parse / render / diff both files
vioslib/vios.py         ssh/scp to the VIOS: run() as padmin, root() via oem_setup_env
tests/test_snmpconf.py  22 tests against the real factory and hand-made files
tests/test_vios_snmp.py CLI end to end against a fake VIOS
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
