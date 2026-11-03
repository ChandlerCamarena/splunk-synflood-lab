# SYN Flood Detection with Splunk on RHEL 9

A home lab that forwards Linux system and audit logs from a STIG-hardened RHEL 9
host to a separate Splunk indexer using the Splunk universal forwarder, then
detects a SYN flood denial-of-service attack in Splunk from the forwarded kernel
log data and fires a scheduled alert on it.

Built on QEMU/KVM on an Arch Linux host. Everything below was actually run; the
limitations section states what was not.

## Architecture

```
  Arch Linux host (attacker + hypervisor)
  192.168.122.1 on virbr0 (libvirt NAT)
        |
        |  hping3 SYN flood, spoofed sources, to TCP 9999
        v
  +-------------------------+          UF ships logs           +-------------------------+
  |  rhel9-stig             |   TCP 9997 (forwarder to idx)    |  splunk                 |
  |  RHEL 9.8, STIG + FIPS  | -------------------------------> |  RHEL 9.8               |
  |  192.168.122.229        |                                  |  Splunk Enterprise      |
  |  universal forwarder    |                                  |  10.6.1.1 (Trial lic.)  |
  |  (runs as root)         |                                  |  192.168.122.38         |
  |                         |                                  |  receiver 9997          |
  |  python3 http.server    |                                  |  web UI 8000            |
  |  listens on 9999        |                                  |  index=main             |
  +-------------------------+                                  +-------------------------+

  Both VMs on the same libvirt NAT network 192.168.122.0/24.
```

## Environment

| Component | Detail |
|---|---|
| Hypervisor host | Arch Linux, QEMU/KVM, libvirt, virt-manager |
| Indexer VM | `splunk`, RHEL 9.8 (Plow), 6 GB RAM, 4 vCPU, 40 GB disk |
| Indexer software | Splunk Enterprise 10.6.1.1 (build b2ae2962645c), Enterprise Trial license |
| Forwarder VM | `rhel9-stig`, RHEL 9.8, DISA STIG hardened, OpenSSL FIPS mode, fapolicyd enforcing, `/home` mounted noexec |
| Forwarder software | Splunk universal forwarder 10.6.1.1 (build b2ae2962645c), runs as root |
| Network | libvirt NAT, 192.168.122.0/24 |
| Attacker | Arch host, hping3 3.0.0 |

## Indexer setup (splunk VM)

Installed Splunk Enterprise from the vendor RPM to `/opt/splunk`, runs as the
`splunk` user under systemd (`Splunkd.service`), boot-start enabled.

Enabled the forwarder receiver:

```
sudo -u splunk /opt/splunk/bin/splunk enable listen 9997
```

Firewall scoped to the lab subnet only (receiver and web UI reachable from
192.168.122.0/24, management 8089 and kvstore 8191 closed to the network):

```
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.122.0/24" port port="9997" protocol="tcp" accept'
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.122.0/24" port port="8000" protocol="tcp" accept'
sudo firewall-cmd --reload
```

The Enterprise Trial license is used deliberately. The Splunk Free license
disables alerting, which would break the detection alert below, so the lab stays
on the 60-day Trial where scheduled alerts fire.

## Forwarder setup (rhel9-stig)

The forwarder RPM was downloaded on the host (the STIG box has broken DNS, see
limitations) and copied over with scp. Installed with `rpm -ivh` because
`dnf` refused the package under the STIG `gpgcheck` policy (Splunk's signer key
was not imported); the signature is present but the signer key was not verified
(`NOKEY`). In production you import the vendor GPG key and let dnf verify.

fapolicyd is enforcing on this host. After install, the trust database was
refreshed so the new binaries are allowed to execute:

```
sudo fapolicyd-cli --update
```

The forwarder runs as **root**, not the default `splunkfwd` user, so it can read
`/var/log/audit/audit.log` (mode 0600, root only) without weakening the STIG
audit-log permissions. Reconfigured with:

```
sudo /opt/splunkforwarder/bin/splunk disable boot-start
sudo chown -R root:root /opt/splunkforwarder
sudo /opt/splunkforwarder/bin/splunk enable boot-start -user root -systemd-managed 1
```

### outputs.conf

`/opt/splunkforwarder/etc/system/local/outputs.conf`

```
[tcpout]
defaultGroup = default-autolb-group

[tcpout:default-autolb-group]
server = 192.168.122.38:9997

[tcpout-server://192.168.122.38:9997]
```

### inputs.conf

`/opt/splunkforwarder/etc/system/local/inputs.conf`

```
[default]
host = rhel9-stig.lab.test

[monitor:///var/log/messages]
disabled = false
index = main
sourcetype = linux_messages_syslog

[monitor:///var/log/secure]
disabled = false
index = main
sourcetype = linux_secure

[monitor:///var/log/audit/audit.log]
disabled = false
index = main
sourcetype = linux_audit
```

Verified the forwarder connected (`Active forwards: 192.168.122.38:9997`) and
that all three sources arrive on the indexer:

```
index=main host=rhel9-stig* | stats count by source
```

Result: `/var/log/audit/audit.log`, `/var/log/messages`, `/var/log/secure` all
present.

## The attack

A SYN flood exhausts the target's half-open connection backlog, not its
bandwidth. Each SYN makes the kernel allocate a request entry in the SYN queue
of the listening socket and reply with a SYN-ACK; spoofed sources never send the
final ACK, so entries sit until they time out and the queue fills. When the
queue overflows and `net.ipv4.tcp_syncookies=1` (set by the STIG baseline), the
kernel engages SYN cookies and logs the event. That log line is the detection
signal.

Setup on the target (non-persistent, demo only):

```
sudo firewall-cmd --add-port=9999/tcp
python3 -m http.server 9999 --bind 0.0.0.0
```

The listener exists only to hold a listening socket with a small backlog to
overflow.

Attack from the Arch host:

```
sudo hping3 -S -p 9999 --flood --rand-source 192.168.122.229
```

`-S` sets the SYN flag, `-p 9999` targets the listener, `--flood` sends as fast
as possible, `--rand-source` spoofs a random source IP per packet so the target
never gets an ACK and the host never sends a RST that would free the backlog.
Roughly 19 to 39 million packets per run.

## Detection

The kernel logged, in `/var/log/messages`, forwarded as `linux_messages_syslog`:

```
Nov  2 18:03:55 rhel9-stig kernel: TCP: request_sock_TCP: Possible SYN flooding on port 0.0.0.0:9999. Sending cookies.
```

`0.0.0.0:9999` is Linux denoting the wildcard listening socket, not a source
address.

### Baseline search

```
index=main host=rhel9-stig* | timechart span=1m count by sourcetype
```

### Detection search

```
index=main host=rhel9-stig* "Possible SYN flooding"
```

### Alert

Saved as a scheduled alert `SYN Flood Detected - rhel9-stig`:

- Schedule: cron `*/1 * * * *` (every minute)
- Time range: Last 5 minutes
- Trigger: Number of Results is greater than 0
- Throttle: 60 seconds
- Action: Add to Triggered Alerts, severity High

Confirmed firing end to end: re-ran the flood, the scheduled search ran within a
minute, and the alert populated Trigger History (see evidence).

### Detection logic and false-positive profile

The alert means the kernel's SYN backlog overflowed, not that an attack is
confirmed. A legitimate traffic spike against an under-provisioned service (small
`somaxconn` or listen backlog) can log the same message. An analyst separates
flood from load by correlating source-IP diversity and SYN rate. The detection
misses a low-rate flood that never overflows the backlog, and a flood against a
closed port (no listening socket, no queue, no message).

## Evidence

| File | Shows |
|---|---|
| `baseline.png` | Flat event timechart before the attack |
| `hping-flood.png` | hping3 sending the SYN flood from the host |
| `half-open.png` | `ss` SYN-RECV count pinned during the flood |
| `detection-event.png` | Splunk search returning the kernel SYN-cookie event |
| `triggered-alert.png` | Alert Trigger History, fired instances |

## Reproduction

1. Build two RHEL 9.8 VMs on libvirt NAT: `splunk` (indexer) and a log source.
2. On `splunk`: install Splunk Enterprise, `splunk enable listen 9997`, scope
   firewalld to the lab subnet for 9997 and 8000, stay on the Enterprise Trial.
3. On the source: install the universal forwarder, refresh fapolicyd trust if
   enforcing, run as root if forwarding root-only logs, write `outputs.conf`
   (indexer:9997) and `inputs.conf` (the log files above).
4. Confirm `index=main host=<source>*` returns `/var/log/messages`,
   `/var/log/secure`, `/var/log/audit/audit.log`.
5. On the source: open a demo port and start a listener on it.
6. From the attacker: `sudo hping3 -S -p <port> --flood --rand-source <source-ip>`.
7. Search `index=main host=<source>* "Possible SYN flooding"` and save it as a
   scheduled alert.

## Limitations

- Single all-in-one Splunk node (indexer, search head, and web on one VM). Not a
  distributed deployment.
- Thresholds are lab-only. The alert triggers on a single cookie message
  (count greater than 0); production would require sustained or correlated
  signal.
- The 60-second throttle against a 60-second schedule and a 5-minute window
  causes the alert to fire on consecutive minutes while one event ages out of
  the window. Production would widen the throttle or narrow the window.
- Detection is binary (message present or absent), not a measured SYN rate. It
  relies on the kernel engaging SYN cookies, which the STIG baseline enables.
  The kernel rate-limits the message, so a sustained flood logs it only
  periodically.
- The universal forwarder runs as root to read STIG-protected audit logs. An
  alternative is a dedicated reader granted access via filesystem ACLs.
- The forwarder RPM was installed with the signer key unverified (`NOKEY`).
  Production imports the vendor GPG key first.
- Port 9999 was opened non-persistently on the target for the demonstration
  only.
- STIG hardening broke DNS on the source VM; the lab works around it with
  IP-based forwarding and local package install (`--disablerepo` / `rpm`).
- The Enterprise Trial license lasts 60 days. After that it reverts to Free,
  where alerting is disabled; the alert must be re-licensed to keep firing.
```
