# remoteusb

`remoteusb` carries USB/IP between trusted Windows or Linux computers using
[Groupnet](https://github.com/napbat/groupnet): keyed rendezvous, hole punching,
**direct-preferred connections with relay fallback**, and mutually authenticated
TLS with exact peer-certificate pins. Existing OS USB/IP tools and drivers still
export the physical device and emulate the receiving controller. remoteusb does
**not** install drivers, change firewalls, or bind exporting devices. Explicit
Windows `connect --attach BUSID` invokes the installed receiving client.
There is no insecure mode or legacy direct-TLS endpoint configuration.

## Setup guide: start here

For a Windows-to-Windows YubiKey connection, follow these steps in order:

### Downloads to install first

Choose **x64** for Intel/AMD Windows PCs, or **ARM64** for Windows on ARM.
These links point to official releases; choose the installer asset for your architecture.

| Install on | Required download | What it provides |
| --- | --- | --- |
| PC holding the physical USB device | [Download usbipd-win](https://github.com/dorssel/usbipd-win/releases/latest) — choose the x64 or ARM64 `.msi` | USB exporter driver/service and `usbipd` command |
| PC receiving the remote USB device | [Download usbip-win2](https://github.com/vadimgrn/usbip-win2/releases/latest) — choose the x64 or ARM64 installer `.exe` | Virtual USB host-controller driver and `usbip.exe` |
| Machine building remoteusb only | [Rust installer (rustup)](https://rustup.rs/) and [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) | Rust compiler plus Windows C++ linker/SDK; select **Desktop development with C++** |

The rendezvous-only host needs **neither USB driver**. Runtime endpoints do not
need Rust or Build Tools if you copy the built `remoteusb.exe` to them.
remoteusb itself is currently [built from this checkout](#build-and-prerequisites);
there is no remoteusb installer download provided by this guide.

Install only the driver needed for each role. Review the linked release notes and
installer prompts: receiving-driver installation can restart USB hubs, and
usbipd-win installs a firewall rule that must be restricted before sharing devices.
Do not disable Secure Boot or driver-signature enforcement. Review the
[usbip-win2 release notes and known issues](https://github.com/vadimgrn/usbip-win2/releases/latest)
before installing; a listed release is not a hardware-compatibility certification.

### Setup order

1. [Build remoteusb](#build-and-prerequisites), using the required local Groupnet
   checkout, and install the USB/IP driver/tool for each machine's role.
2. [Generate credentials once](#generate-credentials-once) in a protected directory.
   [Distribute only the required files](#distribute-the-minimum-files) to each host.
3. [Start rendezvous](#1-start-rendezvous--relay) on a machine reachable by both PCs.
4. [Isolate and export the device](#2-isolate-and-export-the-yubikey), then run
   `remoteusb serve` on the PC holding the physical YubiKey.
5. [Start the receiver and attach](#3-start-the-receiver-and-attach) with
   `remoteusb connect --attach BUSID` and the installed Windows usbip-win2 driver.
6. [Check the selected path](#direct-versus-relay-testing-and-endpoint-options).
   Detach the device safely before stopping the tunnel.

| Role | What runs there | Network requirement |
| --- | --- | --- |
| Rendezvous host | `remoteusb rendezvous` | TCP 7443 reachable by both endpoints |
| Exporter, with physical USB device | `usbipd-win` and `remoteusb serve` | Outbound rendezvous access; direct TCP candidates when permitted |
| Receiver, where applications use the device | `usbip-win2` and `remoteusb connect` | Outbound rendezvous access; local USB/IP listener on loopback |

The rendezvous role may share a machine with an endpoint if it remains reachable.
Direct traffic bypasses the relay; NAT/firewall restrictions may require relaying.
For Linux, use the [Linux export/receive instructions](#linux-export-and-receive).
Without drivers or hardware, start with the [hardware-free checks](#hardware-free-verification).

## Architecture and trust boundaries

```text
Exporting PC                                      Receiving PC
physical YubiKey                                 application
     |                                                |
USB/IP exporting driver                          USB/IP receiving driver
     |                                                |
loopback backend :3240                           loopback listener :3240
     |                                                |
remoteusb serve ===== authenticated Groupnet ===== remoteusb connect
                         direct preferred
                                |
                      rendezvous / relay :7443
                         fallback when needed
```

Both endpoints register with the same keyed rendezvous service. Groupnet attempts
a direct hole-punched link by default, and uses its relay when a direct path is
unavailable. `--relay-only` explicitly forces the relay for diagnostics. The
rendezvous service allowlists the two configured node IDs; there is no open
admission. Sharing the network key is **not** sufficient to impersonate the
endpoint: TLS must validate the private CA and the exact public peer leaf, and the
authorized node ID and remoteusb application preamble must match before `serve`
opens the USB/IP backend. Both certificates use the DNS SAN `groupnet.peer` and
both TLS server/client EKUs because either endpoint can initiate a Groupnet link.

Each local USB/IP TCP connection maps to one independent Groupnet Ordered stream
and one exporter backend connection. Discovery and attach use separate streams.
The transport preserves binary bytes, backpressure, and TCP half-closes. Capacity
limits include pending stream setup; setup timeouts are **not** idle-device
timeouts. There is no automatic USB stream reconnection: after a broken connection,
detach stale imported ports and explicitly attach again.

The workspace uses Rust 2024 and resolver 3. Dependency direction is
`remoteusb-cli -> remoteusb-transport -> Groupnet`; existing USB/IP driver policy
remains outside the transport. Logs contain connection metadata and successful
stream paths (`Direct` or `Relay`), not payloads or key contents.

## Build and prerequisites

Install [rustup](https://rustup.rs/) and the pinned **Rust 1.99.0** toolchain from
`rust-toolchain.toml`. Windows requires the MSVC toolchain and Microsoft C++ build
prerequisites; Linux requires your distribution's C compiler/linker.

Groupnet is unpublished. This integration uses the workspace path dependency
`../../napbat/groupnet/crates/groupnet`, with this required checkout layout:

```text
Git/
  coconutbird/remoteusb/       # this repository
  napbat/groupnet/            # Groupnet workspace
```

The Groupnet checkout must contain revision
`82b8595a5e196327d9e1b760dfd43979f932461e` and be checked out at that revision.
That revision currently exists locally but is **not published on the remote**;
a fresh clone or CI runner cannot fetch it until the Groupnet owner publishes
the commit. Existing developers with the object can prepare it from remoteusb:

```sh
git -C ../../napbat/groupnet checkout 82b8595a5e196327d9e1b760dfd43979f932461e
```

Do not substitute an older revision or assume a normal Cargo fetch supplies it.
After publication, obtain the Groupnet checkout at the layout above and select
the exact revision before building. GitHub read access to `napbat/groupnet` is
required if it is private. CI is configured to check out both repositories at
this layout and the required Groupnet revision; it likewise requires publishing
that commit first. For private-repository CI, configure the optional
`GROUPNET_READ_TOKEN` repository secret with read-only Groupnet access. Never put
tokens in Cargo manifests or command-line URLs.

From this repository:

```sh
cargo +1.99.0 build --release --locked -p remoteusb-cli
cargo +1.99.0 run --locked -p remoteusb-cli -- --help
cargo +1.99.0 run --locked -p remoteusb-cli -- init --help
cargo +1.99.0 run --locked -p remoteusb-cli -- rendezvous --help
cargo +1.99.0 run --locked -p remoteusb-cli -- serve --help
cargo +1.99.0 run --locked -p remoteusb-cli -- connect --help
```

The binary is `target\release\remoteusb.exe` on Windows and
`target/release/remoteusb` on Linux. Put it on PATH or substitute its full path in
the examples. Runtime computers need the binary and their USB/IP tools/drivers,
not Rust or Cargo. `remoteusb --version` prints the version.

Install external tools yourself, following their upstream instructions:

- **Windows exporter:** [dorssel/usbipd-win](https://github.com/dorssel/usbipd-win)
  supplies the `usbipd` service and CLI, **not** a native Windows receiving driver.
  Its installer also adds a local-subnet firewall rule; independently restrict
  raw USB/IP port 3240 before sharing devices.
- **Windows receiver:** [vadimgrn/usbip-win2](https://github.com/vadimgrn/usbip-win2)
  supplies the native receiving controller and `usbip.exe`. Use a Microsoft-signed
  release for your supported architecture/Windows version. Follow upstream's
  restore-point and installation precautions: USB hubs can restart. Retain
  Secure Boot and driver-signature enforcement; do not enable test signing or
  follow old unsigned-driver guidance from `cybernhl/usbip-win`.
- **Linux:** install your distribution's `usbip` userspace tools and use a kernel
  with `usbip_host` (export) or `vhci_hcd` (receive). On Ubuntu, package guidance
  includes `sudo apt install linux-tools-generic linux-cloud-tools-generic`;
  names vary by distribution/kernel. See the
  [Linux USB/IP README](https://github.com/torvalds/linux/blob/master/tools/usb/usbip/README)
  and [manual](https://github.com/torvalds/linux/blob/master/tools/usb/usbip/doc/usbip.8).

On Windows, install only the needed role, reviewing installer/elevation prompts:

```powershell
# On the PC with the physical device:
winget install --exact --id dorssel.usbipd-win --source winget
# On the PC that will import the device:
winget install --exact --id vadimgrn.usbip-win2 --source winget
```

If using winget instead of the download links, check the offered version with
`winget show --exact --id vadimgrn.usbip-win2 --source winget` and compare it with
the upstream release notes; package feeds can lag. Driver installation is a
**manual, opted-in system action**, never part of proxy startup. Do not
install/restart drivers during critical USB work. Binding/attaching and firewall
policy may require administrator/root rights; remoteusb itself can run as an
ordinary account with access to its keys and unprivileged sockets.

## Generate credentials once

Provision on a trusted machine. `init` creates a **new** directory only and refuses
an existing directory, even an empty one. It never overwrites files. On Unix it
creates the directory with mode 0700 and every file with mode 0600 (a restrictive
umask can narrow these further). Private keys are unencrypted; file access is
part of the security boundary.

**On Windows, init does not modify NTFS ACLs.** First create a restricted parent
folder so the new credentials directory inherits owner/SYSTEM-only access:

```powershell
New-Item -ItemType Directory -Path .\remoteusb-private
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
icacls .\remoteusb-private /inheritance:r
icacls .\remoteusb-private /grant:r "${identity}:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F"
# credentials must not already exist; the parent must exist.
remoteusb init --out .\remoteusb-private\credentials
icacls .\remoteusb-private\credentials\exporter.key
icacls .\remoteusb-private\credentials\receiver.key
icacls .\remoteusb-private\credentials\network.key
```

Inspect the resulting ACLs before distributing anything. A Bash umask or Unix
mode is not a substitute for an NTFS ACL. Service accounts need access under
that account rather than an unrelated interactive user's identity. Local
administrators/root remain trusted. `remoteusb` does not change account/security
settings; the `icacls` commands above are deliberate administrator-managed steps.

On Linux:

```sh
umask 077
remoteusb init --out ./credentials
```

The six generated files are:

| File | Purpose | Secret? |
| --- | --- | --- |
| `ca.pem` | Dedicated public trust root | No |
| `exporter.pem` | Exporter public certificate and exact receiver-side pin | No |
| `exporter.key` | Exporter private key | **Yes** |
| `receiver.pem` | Receiver public certificate and exact exporter-side pin | No |
| `receiver.key` | Receiver private key | **Yes** |
| `network.key` | 32 secure-random bytes encoded as 64 hexadecimal digits | **Yes** |

The CA signing key is used in memory and **never saved**. `init` prints paths and
next commands, not secrets. If provisioning fails after directory creation, it
can leave partial output; inspect it and use a new output path on retry. Do not
reuse an incomplete credentials set.

### Distribute the minimum files

Copy through an authenticated confidential channel, into separately protected
directories on each machine. Do **not** copy the entire provisioning directory to
all machines:

| Machine | Files to copy into its `--credentials` directory |
| --- | --- |
| Rendezvous/relay host | **Only `network.key`** |
| Exporter | `ca.pem`, `exporter.pem`, **`exporter.key`**, `receiver.pem`, **`network.key`** |
| Receiver | `ca.pem`, `receiver.pem`, **`receiver.key`**, `exporter.pem`, **`network.key`** |

The relay does not require or read endpoint TLS private keys or certificates.
It participates in keyed rendezvous/relay routing; keep the shared network key
private. Neither endpoint needs the other's private key. Protect deployment
parents/ACLs before copying on Windows; inspect the key ACLs afterward. On Unix,
use `chmod 700 DIRECTORY` and `chmod 600 DIRECTORY/*.key`.

Never commit keys, upload them to an issue, or print them into logs. Preserve the
public peer certificates exactly: replacing a leaf requires updating the opposite
endpoint's pin. Plan replacement before certificate expiry; clocks must be
correct. There is no CRL/OCSP revocation or CA-key retention/renewal workflow.
To replace a compromised deployment, provision a fresh set, redistribute only
the required files, and restart endpoints/relay to terminate old sessions.

## Windows-to-Windows YubiKey setup

These commands assume separate trusted PCs and a reachable rendezvous/relay host.
Keep a backup login method. Start with a non-critical account/device; actual
YubiKey, driver, FIDO2/WebAuthn, PIV, OpenPGP, and OTP compatibility is **not**
hardware-verified by this project. Physical touch must occur at the physical key.

### 1. Start rendezvous / relay

On a host reachable by both PCs, with only `network.key` in `relay-credentials`:

```powershell
remoteusb rendezvous --listen 0.0.0.0:7443 --credentials .\relay-credentials --exporter-id exporter --receiver-id receiver
```

Without `--listen`, rendezvous binds `127.0.0.1:7443` for same-machine testing.
Public hosting must be explicit. Permit **TCP 7443** in your existing
firewall/routing policy; if behind NAT, provide reachable forwarding to this host.
Use an actual numeric address reachable from both endpoints. In the next commands,
**replace `203.0.113.10`** (documentation-only, not a real relay) with that address.
DNS names are not accepted by `--rendezvous`; resolve the intended host first.

### 2. Isolate and export the YubiKey

Before binding, restrict raw USB/IP TCP **3240** to the exporter itself.
`serve` rejects non-loopback `--backend`, but cannot stop `usbipd` from separately
listening on all interfaces. Review/restrict usbipd-win's installed firewall rule:
allow the required loopback access and deny non-loopback ingress to raw 3240.
Never publish raw USB/IP to a LAN or the Internet. Do not disable the firewall or
other system protections to make sharing work.

In an administrator PowerShell on the PC with the physical key:

```powershell
usbipd list
# Replace 1-2 with THE YUBIKEY'S BUSID from the list.
usbipd bind --busid 1-2
```

Binding persists across reboots. Do not bind your management keyboard, network
adapter, or system disk. Binding/exporting transfers device ownership; exclusive
attachment is expected, not simultaneous local and remote use. The installed
usbipd service is the backend on 3240.

Leave this running in another exporter terminal:

```powershell
remoteusb serve --backend 127.0.0.1:3240 --rendezvous 203.0.113.10:7443 --credentials .\exporter-credentials
```

### 3. Start the receiver and attach

On the Windows receiving PC, run in an administrator terminal and leave it running.
Replace `1-2` with the exported device's BUSID:

```powershell
remoteusb connect --listen 127.0.0.1:13240 --rendezvous 203.0.113.10:7443 --credentials .\receiver-credentials --attach 1-2
```

This uses installed **usbip-win2**, not `usbipd attach --wsl`. remoteusb passes the
actual loopback listener address/port to `usbip.exe`, attaches once, and reports
the imported port. It finds the tool at `%ProgramFiles%\USBip\usbip.exe`;
`--usbip "C:\path\usbip.exe"` overrides that location and requires `--attach`.
Missing drivers, privilege failures, and attachment errors are fatal; there is
no automatic retry or reattachment. Linux attachment remains manual.

Omit `--attach` to retain a plain tunnel, discover devices, or manage attachment
yourself. For the listener above, discovery is:

```powershell
usbip.exe --tcp-port 13240 list --remote 127.0.0.1
```

Always point discovery and attach at the **local loopback tunnel**, never the
real exporter address. Install the normal receiving-side device application/
driver as needed. Touch the physical YubiKey when the remote application requests
it; PIN/user verification depends on the application and device mode.

With `--attach`, stop application activity and press Ctrl-C: remoteusb detaches
**only the port returned by its own attach**, then stops the tunnel. It also
attempts that cleanup if the fabric terminates. Storage still requires a safe
flush/unmount first. Forced process termination cannot run cleanup; a driver
timeout or an invalid port response leaves attachment state uncertain and
requires inspection with `usbip.exe port`.

Without `--attach`, detach manually using the imported PORT (example port 1).
Unbind on the exporter only when you want to stop sharing:

```powershell
usbip.exe detach -p 1
# On the exporter, only after detach, to stop sharing:
usbipd unbind --busid 1-2
usbipd list
```

See [usbip-win2 usage](https://github.com/vadimgrn/usbip-win2#use-usbipexe-to-attach-remote-devices)
for port numbering and syntax. Follow usbipd-win's own
[unbind behavior](https://github.com/dorssel/usbipd-win/blob/master/Usbipd/Program.cs);
unbinding an attached device can surprise-remove it.

## Direct versus relay testing and endpoint options

- Default mode is **DirectPreferred**: hole punching/direct candidates first,
  relay fallback when direct connectivity cannot be established. Relay fallback
  does not mean reattaching an already broken USB session automatically.
- For a deterministic relay-path test, add `--relay-only` to **both** the `serve`
  and `connect` commands above. Run `usbip.exe --tcp-port 13240 list -r 127.0.0.1` and inspect the
  successful stream log for `Relay`. Remove the flag and restart both endpoints
  to test direct-preferred mode; `Direct` demonstrates the actual selected path,
  while `Relay` demonstrates fallback. A bound listener or registration alone
  does not demonstrate stream transfer, hardware compatibility, or a direct path.
- `--candidate-bind IP:PORT` is repeatable on both endpoints, with up to four
  binds; the default is `0.0.0.0:0`. The first bind supplies rendezvous registration
  and source connectivity and must match the rendezvous address family. For an
  IPv6 rendezvous, explicitly pass `--candidate-bind "[::]:0"`. Additional binds
  provide retained direct candidate listeners on suitable local interfaces.
  Candidates, rendezvous, and relay are **TCP-only**, not UDP. Permit the relevant
  TCP traffic under your existing network policy. NAT/firewall behavior determines
  whether direct hole punching succeeds; reachable rendezvous/relay is still
  required for reliable fallback. No fixed public exporter TLS listener or
  `--remote`/`--server-name` is used.
- Aliases must agree end to end. For example rendezvous
  `--exporter-id key-pc --receiver-id work-pc` requires serve
  `--local-id key-pc --peer-id work-pc` and connect
  `--local-id work-pc --peer-id key-pc`. Certificate filenames remain
  exporter/receiver regardless of aliases. Node IDs are exact allowlist entries,
  not a substitute for CA validation and certificate pins.
- Both endpoint roles default to `--max-connections 64` and
  `--connect-timeout-secs 10`; zero is rejected. Limits count streams, including
  setup, not physical devices. There is no idle timeout for an attached key.
- Actual rendezvous/listener addresses are logged, including ephemeral ports.
  Startup/fatal fabric errors cause nonzero exits; individual failed stream
  attempts are reported. Ctrl-C signal-handler failures are fatal, not silently
  treated as successful shutdown.

### Same-machine testing and port collisions

Use `--rendezvous 127.0.0.1:7443` on both endpoints with the default loopback
rendezvous for local tests. If an exporter already occupies 3240, `connect` cannot
bind its default socket on the same machine. Prefer separate PCs. If the backend
binds **only** `127.0.0.1`, and your OS supports the second loopback IP:

```powershell
remoteusb connect --listen 127.0.0.2:3240 --rendezvous 127.0.0.1:7443 --credentials .\receiver-credentials --relay-only
usbip.exe list -r 127.0.0.2
# Use -r 127.0.0.2 for attach too.
```

This fails if the backend binds a wildcard address such as `0.0.0.0:3240`, which
can also occupy the second loopback address; use separate machines in that case.
Linux tools can instead use another port:

```sh
remoteusb connect --listen 127.0.0.1:3241 --rendezvous 127.0.0.1:7443 --credentials ./receiver-credentials
usbip --tcp-port 3241 list --remote 127.0.0.1
sudo usbip --tcp-port 3241 attach --remote 127.0.0.1 --busid 1-2
```

Do not assume every Windows receiving-tool release supports custom ports.
A synthetic loopback backend can exercise transport without driver installation
or hardware binding, but is not evidence of real USB/IP hardware compatibility.

## Linux export and receive

Independently isolate raw 3240 with your existing firewall manager; keep SELinux
and other protections enabled. On a Linux exporter:

```sh
sudo modprobe usbip_host
sudo usbipd -D
usbip list --local
sudo usbip bind --busid 1-2
remoteusb serve --backend 127.0.0.1:3240 --rendezvous 203.0.113.10:7443 --credentials ./exporter-credentials
```

Replace the relay IP and BUSID as above. If usbipd is already managed by a system
service, use it instead of starting a second daemon. remoteusb stays foreground.
On a Linux receiver, start `remoteusb connect` as above with
`--credentials ./receiver-credentials`; in another terminal:

```sh
sudo modprobe vhci_hcd
usbip list --remote 127.0.0.1
sudo usbip attach --remote 127.0.0.1 --busid 1-2
usbip port
# Replace 0 with the actual local imported port:
sudo usbip detach --port 0
# On exporter, only after safe detach:
sudo usbip unbind --busid 1-2
```

Windows and Linux imported port numbers need not match. Mixed-OS and particular
device/driver combinations need independent qualification.

## Hardware-free verification

These commands exercise generated credentials and real Groupnet nodes with
loopback USB/IP backends. They do not install drivers, bind devices, or change
firewall settings:

```sh
cargo +1.99.0 test --workspace --locked
cargo +1.99.0 clippy --workspace --all-targets --locked -- -D warnings
cargo +1.99.0 fmt --all -- --check
```

During this integration, actual `init`, `rendezvous`, `serve`, and `connect` CLI
processes were also exercised on Windows:

- Direct and forced-relay paths returned the exact USB/IP device-list response
  from a synthetic backend.
- Streams preserved 2 MiB upstream and 1 MiB downstream binary transfers and
  half-closes; four concurrent connections to the same peer also passed.
- An established stream remained usable after 21 seconds without USB data.
- A wrong peer-certificate pin was rejected without opening the backend.
- Re-running `init` against an existing directory left its credentials unchanged.
- The release executable passed a separate relayed byte-transfer smoke run.

These automated checks are transport checks, not physical-device or Internet/NAT
qualification. A separate manual Windows loopback test with an explicitly
approved spare USB drive also passed: native attachment through the direct
tunnel, a 16 MiB file write and flush, then an exact SHA-256 match after volume
dismount/remount and readback. The test file was removed and the original device
mount, sharing, and firewall state restored. This does not qualify physical
relay attachment, YubiKey functions, or cross-machine Internet operation.
Follow the driver setup and discovery/attach steps above to qualify your device.

## Opt-in real-drive integration test

[`crates/remoteusb-cli/tests/usb-drive.rs`](crates/remoteusb-cli/tests/usb-drive.rs)
accepts a drive letter (`D`, `D:`, or `D:\`), a Windows volume GUID path such as
`\\?\Volume{12345678-1234-1234-1234-123456789abc}\`, or an absolute mounted-directory
path through `REMOTEUSB_TEST_DRIVE`. Select the **receiving-side volume already
attached through remoteusb**, not the original locally attached exporter volume.
Check `usbip.exe port` and the selected volume before running it.

```powershell
$env:REMOTEUSB_TEST_DRIVE = 'D:'
cargo +1.99.0 test --locked -p remoteusb-cli --test usb-drive -- --ignored --nocapture
Remove-Item Env:REMOTEUSB_TEST_DRIVE
```

On Linux, use the receiver's mounted path:

```sh
REMOTEUSB_TEST_DRIVE=/media/remote-usb cargo +1.99.0 test --locked -p remoteusb-cli --test usb-drive -- --ignored --nocapture
```

The test creates a uniquely named temporary directory on that drive, writes and
flushes 16 MiB, closes/reopens the file, and compares every byte. It then overwrites
one interior block, flushes/reopens again, and verifies the changed block,
neighbors, first/last blocks, and unchanged file length. Only its own directory
and file are deleted; existing files are never opened or overwritten.

The hardware case is ignored by default and fails if no target is supplied.
It does not install drivers, bind/attach devices, change mounts or firewalls, or
start/stop the tunnel. The operator establishes which tunnel/path backs the volume;
the test cannot infer that from a drive letter. Reads can use OS caches, so this
is filesystem I/O verification, not proof of power-loss durability.

This Rust hardware case passed on Windows against the approved spare USB drive
mounted through a local direct remoteusb tunnel. Its test file was removed and
the operator restored the original mount/sharing state after the run. The same
test has not yet qualified a physical drive over relay or an Internet path.

## Security, shutdown, and troubleshooting

An authorized receiver gains control of **every device exported by the selected
backend**, not just the BUSID in an example. There are no per-device ACLs or USB
command filters. Use a dedicated backend/trust domain when different devices
require different authorization. Loopback is a machine trust boundary, not a
user boundary: other local users may access the receiver tunnel or raw exporter.
Use trusted endpoints or suitable OS isolation. Endpoint compromise defeats
transport protection; holding a device's private signing keys on the physical
key does not make an untrusted receiving computer safe. An authorized receiver
can invoke whatever operations the key permits, including administrative ones.

The tunnel cannot bypass physical touch/PIN or emulate user presence. See
[Yubico's WebAuthn guide](https://developers.yubico.com/WebAuthn/WebAuthn_Developer_Guide/)
for the authenticator security model. WAN latency, driver behavior, composite or
isochronous devices, resets, and throughput can differ from local USB. Encryption
is not a hardware compatibility guarantee.

**Stop application activity and flush/unmount or safely eject storage before
disconnecting it.** Windows `connect --attach` detaches its owned port on Ctrl-C;
otherwise detach with the receiving USB/IP tool before stopping the tunnel.
Shutdown then closes Groupnet resources; it is
like unplugging a device, not a graceful filesystem unmount. Unexpected loss can
interrupt authentication or lose data. After any broken stream/restart, inspect
imported ports, detach stale attachments, and explicitly attach again. No silent
USB reconnect or device resurrection is attempted.

For failures, check:

1. Driver/tool installation and correct physical BUSID, without changing unrelated
   devices. No hardware or driver installation is performed by remoteusb.
2. Exporter backend availability on loopback 3240 and independent raw-port isolation.
3. Actual listener addresses and same-machine/wildcard port collisions.
4. Reachability of the numeric rendezvous address, relay firewall/routing, matching
   `network.key`, and the exact two allowed IDs. Use `--relay-only` on both ends to
   separate direct-path/NAT problems from stream/authentication problems.
5. Clock/certificate validity, CA, both-EKU `groupnet.peer` leaves, fixed role file
   names, key/certificate pairing, exact opposite public leaf pin, and key ACLs.
   Do not bypass certificate checks to work around errors.
6. Successful `Direct`/`Relay` stream logs, backend discovery replies, exporter
   ownership, and stale receiving ports; consult external driver diagnostics.

Never paste private keys, network keys, or USB payloads into bug reports.
Integration coverage and synthetic process tests address transport boundaries,
not physical YubiKey, Windows/Linux driver, storage, or real-device verification.
No particular hardware compatibility is claimed; qualify your exact OS, driver,
device, and application in a non-critical environment before relying on it.
