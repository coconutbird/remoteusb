# remoteusb

`remoteusb` carries USB/IP between trusted Windows or Linux computers using
[Groupnet](https://github.com/napbat/groupnet). **Direct IP connections are the
default**; optional keyed rendezvous adds discovery, hole punching and relay
fallback. Groupnet authenticates streams with mutual TLS and exact certificate
pins in both modes. Existing OS drivers export and receive physical USB devices.
remoteusb does **not** install drivers or change firewalls. The exporter discovers
connected devices and shares a selected device on demand through installed tools.
Windows `attach` owns an attachment until the foreground receiver exits; a separate
supervisor handles detachment even if that receiver is force-killed.

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
3. [Isolate and export the device](#1-isolate-and-export-the-yubikey), then run
   `remoteusb serve` on the PC holding the physical YubiKey.
4. [List and attach](#2-list-and-attach-from-the-receiver) from the receiving PC.
5. Stop device activity, then press Ctrl-C in the receiving process to disconnect.

| Role | What runs there | Network requirement |
| --- | --- | --- |
| Exporter | `usbipd-win` and `remoteusb serve` | Direct mode: reachable TCP 7443 |
| Receiver | `remoteusb list`, `attach`, or `connect`; usbip-win2 for attachment | Outbound access to exporter; internal loopback USB/IP listener |
| Optional rendezvous host | `remoteusb rendezvous` | Reachable by both endpoints in rendezvous mode |

With an existing router port forward, point TCP 7443 at the exporting PC.
Do not forward raw USB/IP port 3240. If direct reachability is unavailable, use
the [optional rendezvous setup](#optional-rendezvous-and-relay).
For Linux, use the [Linux export/receive instructions](#linux-export-and-receive).
Without drivers or hardware, start with the [hardware-free checks](#hardware-free-verification).

## Architecture and trust boundaries

```text
Physical USB → USB/IP exporter → remoteusb serve :7443
                                        ↕ Groupnet authenticated stream
Application ← USB/IP receiver ← remoteusb attach IP BUSID
                                        ↕ private lifetime pipe
                                 attachment supervisor
```

Direct mode uses native Groupnet TCP with an explicit peer node allowlist.
Transport admission metadata is not itself authenticated: **TLS is the device
access boundary**, with private CA validation, exact peer leaf pins and
`groupnet.peer` server-name validation. The remoteusb marker/reply exchange
completes before `serve` opens the USB/IP backend. There is no separate raw-TLS
socket mode, insecure option, or authentication downgrade.
An unauthenticated connection claiming the allowlisted node ID can occupy the
single bounded adjacent-peer slot and deny new direct connections; the allowlist
does not prove identity or prevent this availability attack. It cannot authorize
USB access without the pinned TLS credentials. Use keyed rendezvous mode when
network-key admission is required before a transport peer is accepted.

Rendezvous mode additionally authenticates discovery/connectivity with a shared
network key and exact node allowlists. Discovery coordinates direct paths;
relay fallback actually forwards encrypted traffic. A network key alone cannot
impersonate an endpoint's pinned TLS identity. Both endpoint certificates need
client and server EKUs.

Each local USB/IP TCP connection maps to one independent Groupnet ordered stream
and exporter backend connection. Streams preserve bytes, backpressure and
half-closes. Setup deadlines do not become device idle timeouts. No broken USB
stream is silently reconnected. An attached receiver exits and requests cleanup
when its device stream ends; a plain `connect` listener can serve multiple streams.

Groupnet owns tunnel flow control: byte-based receive credit, windows of up to
16 MiB per direction drawn from a bounded node-wide memory budget, and
delay-based congestion control that fills high-latency links without building a
standing queue. remoteusb sets only its admission bounds (its memory budget grows
with `--max-connections` so every session's guaranteed floor fits) and sizes every
drop-on-full queue (router link queues, TCP and punch outbound queues) to hold
Groupnet's per-session packet queue for every admitted stream.

Measured against plain TCP through the same latency/bandwidth emulator: 20 ms and
80 ms gigabit downloads reach 117 and 108 MB/s (TCP 120 and 108), 100 Mbit links
run at line rate, and request latency matches TCP; a cold 80 ms gigabit upload
reaches about 82 MB/s while its window ramps. Earlier releases capped a stream at
16 KiB-1 MiB in flight (12 MB/s at 80 ms) or dropped segments locally.
Wire protocol version 3 (Groupnet tunnel version 3) marks the current format;
**update both endpoints**. Older peers cannot complete the TLS handshake with a
version 3 peer and fail after the setup deadline.

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
| Exporter | `ca.pem`, `exporter.pem`, **`exporter.key`**, `receiver.pem`; **`network.key` only for rendezvous mode** |
| Receiver | `ca.pem`, `receiver.pem`, **`receiver.key`**, `exporter.pem`; **`network.key` only for rendezvous mode** |

The relay does not require or read endpoint TLS private keys or certificates.
It participates in keyed rendezvous/relay routing; keep the shared network key
private. Neither endpoint needs the other's private key. Protect deployment
parents/ACLs before copying on Windows; inspect the key ACLs afterward. On Unix,
use `chmod 700 DIRECTORY` and `chmod 600 DIRECTORY/*.key`.

By default, credentials are read from a `credentials` directory **beside the
executable**, independent of the shell's working directory. Override this with
`--credentials DIR`. An IP address never substitutes for provisioned trust.

Never commit keys, upload them to an issue, or print them into logs. Preserve the
public peer certificates exactly: replacing a leaf requires updating the opposite
endpoint's pin. Plan replacement before certificate expiry; clocks must be
correct. There is no CRL/OCSP revocation or CA-key retention/renewal workflow.
To replace a compromised deployment, provision a fresh set, redistribute only
the required files, and restart endpoints/relay to terminate old sessions.

## Windows-to-Windows YubiKey setup

The default setup needs a directly reachable exporter, not a rendezvous server.
Keep a backup login method. Physical touch still happens on the physical key.
Authentication protocols and particular OS/driver/device combinations need
independent qualification; USB enumeration alone does not prove every key mode.

### 1. Isolate and export the YubiKey

Before binding, restrict raw USB/IP TCP **3240** to the exporter itself.
`serve` rejects non-loopback `--backend`, but cannot stop `usbipd` from separately
listening on all interfaces. Review/restrict usbipd-win's installed firewall rule:
allow the required loopback access and deny non-loopback ingress to raw 3240.
Never publish raw USB/IP to a LAN or the Internet. Do not disable the firewall or
other system protections to make sharing work.

In an administrator PowerShell on the exporting PC, leave this running:

```powershell
remoteusb serve --credentials .\exporter-credentials
```

By default **all exportable connected devices are available** to the authorized
receiver. Startup and `list` do not bind devices. A receiver's attach request
binds only its selected device. Hubs and disconnected devices are not candidates.
Newly plugged devices appear on the next discovery request.

To limit which devices receivers may select:

```powershell
remoteusb serve --pick --credentials .\exporter-credentials
remoteusb serve --device 1-2 --device 6-3 --credentials .\exporter-credentials
```

`--pick` displays a numbered list and accepts comma-separated numbers. An empty
selection cancels startup. `--device` may be repeated or comma-separated;
restrictions use BUSIDs, not permanent physical identities. Check them after
moving/replacing hardware. Binding critical keyboards, network adapters, or
mounted storage can interrupt the exporting PC; restrict devices when appropriate.

After disconnection, the exporter restores sharing it created for that session.
Preexisting sharing remains unchanged. The installed USB/IP backend must manage
these same local devices. Windows uses `usbipd state` and binds without `--force`.
No interactive elevation, driver installation, or firewall changes occur.

Do not run external bind/unbind commands while remoteusb owns a device session.
The installed management APIs cannot atomically prove ownership against concurrent
administrator changes. remoteusb coordinates its own exporter processes with
per-BUSID OS file locks (`%ProgramData%\\remoteusb\\locks` on Windows,
`/run/lock/remoteusb` on Linux); the exporter needs permission to create these.
Lock files contain no credentials and remain after the OS releases their locks.
Ambiguous mutation/restore results are reported instead of guessing which sharing
registration may be removed.

The backend defaults to `127.0.0.1:3240`. Allow TCP 7443 in the exporter firewall
and forward it from the router if needed. `serve` defaults to `0.0.0.0:7443`;
use `--listen "[::]:7443"` for an IPv6 listener.

### 2. List and attach from the receiver

Assuming receiver credentials are beside the executable, replace `203.0.113.10`
with the real exporter IP (the example address is documentation-only):

```powershell
.\remoteusb.exe list 203.0.113.10
.\remoteusb.exe attach 203.0.113.10 1-2
```

`list` reads the exporter's connected-device inventory over an authenticated
tunnel and exits; it needs no receiving USB/IP driver. Both endpoints must run
the same remoteusb protocol version. `attach` uses installed **usbip-win2**, chooses its loopback port
internally, and stays in the foreground. Run attachment in an administrator
terminal when required by the installed driver. There is no public `detach`
command: stop device activity and press Ctrl-C in the receiver to detach.

Device listings include `STATUS` (`Available`, `Shared`, or `Busy`) and `NAME`.
`Available` means eligible for on-demand sharing, not already bound or guaranteed
compatible. Names use the embedded USB ID database, falling back to the exporter's
OS description; numeric IDs remain visible. Use BUSID to select an attachment.
Native USB/IP device-list requests through a plain tunnel can list only already
shared devices, because unbound devices do not yet have backend USB/IP descriptors.
Use `remoteusb list` to see all permitted candidates without binding them.

Run discovery before attachment. Use one active receiving process per provisioned
node identity; a second independent process with the same identity cannot replace
an incumbent direct connection. A plain tunnel can still carry multiple local
USB/IP streams.

The equivalent combined command is:

```powershell
.\remoteusb.exe connect 203.0.113.10 --attach 1-2
```

`connect IP` without `--attach` is an advanced foreground byte tunnel, not a
persistent background session. It prints its automatically allocated loopback
port; use `--listen 127.0.0.1:13240` if an external client needs a fixed port.
Targets are numeric IPv4/IPv6 addresses, with optional explicit port; port 7443
is the default. For example: `203.0.113.10:8443` or `[2001:db8::1]:7443`.

### Attachment ownership and cleanup

The Windows attachment supervisor is an independent copy of the executable.
It owns a private loopback proxy, its single driver connection, and the attachment.
A private pipe tracks receiver lifetime. On Ctrl-C, receiver failure or force-kill,
the supervisor closes **only its own sockets**, rejects further connections and
cancels retries for that exact private endpoint. It never detaches by a saved USB
port number, which Windows could have reassigned to an unrelated device.
Receiver death during attachment still waits for the attach result before cleanup.
The foreground receiver waits for confirmed cleanup during controlled shutdown.

There is no automatic reattachment. Missing drivers and privilege failures are
reported. The default client is `%ProgramFiles%\USBip\usbip.exe`; use
`--usbip "C:\path\usbip.exe"` with `attach` or `connect --attach` if needed.

usbip-win2's `--once` prevents retries on initial failure, but its disconnect path
can still schedule reattachment. Cleanup after a potentially successful import
therefore requires a positive targeted retry-cancellation acknowledgment and
confirms the private endpoint is no longer imported before releasing its listener.
An initial failure with no reply, or a valid rejected-import reply, releases only
after the attach child has finished and owned sockets have closed.
If driver status/output is ambiguous,
the supervisor reports failure and keeps that endpoint reserved/rejecting while
recovery remains pending; it does not falsely report clean detachment or allow
retries to reach a reused port. See the driver's
[automatic reattachment behavior](https://github.com/vadimgrn/usbip-win2/wiki/How-automatic-reattachment-works).

This cannot recover from power loss, killing both processes, or an external job
manager killing the complete process tree. A driver timeout or ambiguous driver
output can leave unknown attachment state; inspect `usbip.exe port` and use the
driver's recovery tools. Cleanup is unplugging, **not** a graceful filesystem
unmount: flush/unmount storage before ending the receiver. To stop exporting
after a receiver has exited, run `usbipd unbind --busid 1-2` on the exporter.

## Optional rendezvous and relay

When a direct exporter address is unavailable, run keyed rendezvous on a host
reachable by both peers, then opt both endpoints into it:

```powershell
# Rendezvous host: only network.key is needed.
remoteusb rendezvous --listen 0.0.0.0:7443 --credentials .\relay-credentials
# Exporter:
remoteusb serve --rendezvous 203.0.113.10:7443 --credentials .\exporter-credentials
# Receiver:
remoteusb list exporter --rendezvous 203.0.113.10:7443
remoteusb attach exporter 1-2 --rendezvous 203.0.113.10:7443
```

With `--rendezvous`, the positional target is the exporter's **node ID**, not
its IP. Default node IDs are `exporter` and `receiver`. The peers register with
the same keyed server, prefer a direct punched path, and relay when needed.
`--relay-only` forces relay mode and requires `--rendezvous`. Direct mode does
not contact a rendezvous server and does not silently fall back to one.

`--candidate-bind IP:PORT` is rendezvous-only and repeatable up to four times.
Its default unspecified address matches the rendezvous address family. A public
direct listener (`serve --listen`) and `--rendezvous` are mutually exclusive.
If hosting both services on one PC, use different ports. All connectivity is TCP.

In direct mode, use `--peer-id` to override the provisioned remote ID. In
rendezvous mode, the receiver target supplies it; serve still uses `--peer-id`.
`--local-id` changes the local alias, never certificate filenames. CA checks,
exact leaf pins, and node allowlists apply regardless of aliases.

Both roles default to 64 concurrent setup/forwarding tasks and a 10-second
setup deadline (`--max-connections`, `--connect-timeout-secs`). There is no idle
timeout on an attached device. List operations have a bounded discovery deadline.
Plain tunnels and exporters survive individual failed streams; supervised
attachments clean up when their device connection ends.

### Same-machine testing

```powershell
remoteusb serve --listen 127.0.0.1:7443 --credentials .\exporter-credentials
remoteusb list 127.0.0.1 --credentials .\receiver-credentials
remoteusb attach 127.0.0.1 1-2 --credentials .\receiver-credentials
```

The receiver uses an ephemeral loopback port, so the exporting backend can keep
3240. A synthetic backend proves transport behavior, not physical-device support.

## Linux export and receive

Independently isolate raw 3240 with your existing firewall manager; keep SELinux
and other protections enabled. On a Linux exporter:

```sh
sudo modprobe usbip_host
sudo usbipd -D
usbip list --local
sudo remoteusb serve --listen 0.0.0.0:7443 --credentials ./exporter-credentials
```

Replace the exporter IP and BUSID as above. If usbipd is already managed by a
system service, use it instead of starting a second daemon. Automatic attachment
and its cleanup supervisor currently require Windows usbip-win2. On Linux, use
native tools with a foreground plain tunnel:

```sh
remoteusb list 203.0.113.10 --credentials ./receiver-credentials
remoteusb connect 203.0.113.10 --listen 127.0.0.1:13240 --credentials ./receiver-credentials
# In a second terminal:
sudo modprobe vhci_hcd
sudo usbip --tcp-port 13240 attach --remote 127.0.0.1 --busid 1-2
usbip port
# Replace 0 with the actual local imported port:
sudo usbip detach --port 0
```

Windows and Linux imported port numbers need not match. Mixed-OS and particular
device/driver combinations need independent qualification.

Linux managed export requires root/device-driver sysfs permissions, installed
`usbip`, `cat`, and `tee` tools, and an already loaded `usbip_host` module.
remoteusb does not load modules. Cleanup restores the original USB configuration
and device/interface drivers when the same
device identity is still present. Hot unplug/replug or concurrent administrative
driver changes cannot be made transactional by these OS APIs; identity changes
produce a cleanup error rather than modifying a replacement device.
Keep the exporter running until attached sessions have disconnected and cleanup
finishes. Killing the exporter or losing power can leave sharing behind; inspect
native USB/IP state before recovery.


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

The direct-first CLI and independent supervisor were also exercised manually on
Windows with usbipd-win 5.3.0 and usbip-win2 0.9.8.1: authenticated device discovery
over direct TCP and forced relay, real YubiKey attachment, and cleanup after
Ctrl-C, killing only the receiver, and exporter loss. Each cleanup left no imported
devices; a nonexistent BUSID failed without retaining a cleanup worker. These were
same-machine checks, not cross-machine Internet or YubiKey authentication-function
qualification.
An additional real-driver smoke killed the receiver while an import awaited its
first reply from a deliberately stalled loopback backend; its supervisor closed
the sockets and exited without creating a device or retaining a reservation.

Managed export verification passed formatting, strict Clippy, and 74 tests on
both Windows and Linux. Manual Windows checks verified all-device discovery
without changing sharing, interactive and explicit restrictions, rejection of
excluded imports before binding, and inventory over direct and forced-relay paths.
An explicitly approved YubiKey test started unshared, bound on receiver selection,
and automatically unshared after receiver force-kill; its original shared state
was then restored by the operator. The updated release also listed all devices
through the public IP from inside the LAN. Linux hardware binding is not qualified:
the available WSL host lacks USB sysfs support, and the actual CLI correctly
reported that prerequisite rather than starting a nonfunctional exporter.

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

## Opt-in real-device WAN test

[`crates/remoteusb-cli/tests/wan.rs`](crates/remoteusb-cli/tests/wan.rs) always
uses real hardware: there is no synthetic device mode. Pass the exporter BUSID
manually. On a Windows machine with usbipd-win and usbip-win2, it runs this
build's actual `serve --device BUSID` and `attach` through a loopback WAN link
with one-way delay and bandwidth pacing, using freshly generated credentials.

```powershell
$env:REMOTEUSB_WAN_DEVICE = '6-8'          # required: exporter BUSID
$env:REMOTEUSB_TEST_DRIVE = 'D:'           # optional: volume it appears as, for file I/O
cargo +1.99.0 test --locked -p remoteusb-cli --test wan -- --ignored --nocapture
Remove-Item Env:REMOTEUSB_WAN_DEVICE, Env:REMOTEUSB_TEST_DRIVE
```

Defaults are 80 ms round-trip time and 50 Mbit/s per direction; override them
with `REMOTEUSB_WAN_RTT_MS` (1–1000) and `REMOTEUSB_WAN_MBIT` (1–1000).
`REMOTEUSB_USBIP` overrides the receiving `usbip.exe`. The test prints
`WAN RESULT key=value` lines for discovery, attachment and, with a drive, the
same 16 MiB write/flush/reopen/verify cycle as the real-drive test. It asserts
completion, data integrity and deadlines, not hardware-specific speeds.

The selected device is shared, attached and then released through the exporter's
own on-demand lifecycle: the device is taken from the exporter host during the
run, and the test waits until the exporter reports it restored before stopping.
The test never binds, unbinds or detaches devices itself. It is ignored by
default and fails without a device; non-Windows receivers fail explicitly
because automatic attachment requires usbip-win2.

Measured on Windows with a spare USB 3.2 drive (BUSID `6-8`) through this test:

| Emulated link | Volume appears | Verified file I/O |
| --- | --- | --- |
| 1 ms RTT, 1000 Mbit/s | 7.3 s | 3.35 MB/s |
| 80 ms RTT, 50 Mbit/s | 63 s | 0.34 MB/s |

Before the flow-control fix, a single 64 KiB request/response through the same
transport took 3.4 s at 80 ms RTT; it now takes 93 ms, within about 3 ms of the
physical round trip. The remaining WAN cost is USB/IP itself: storage commands
travel as sequential URB round trips, so mounting and file I/O scale with RTT.
Expect interactive devices such as security keys to be responsive and bulk
storage to be usable but latency-bound over the Internet.

## Security, shutdown, and troubleshooting

By default an authorized receiver may select **every exportable connected USB
device** on the exporter. `serve --device` or `--pick` restricts BUSIDs for all
receivers admitted by that exporter; it is not a separate policy per certificate.
Import requests outside the selected set are rejected before binding. USB payloads
are not inspected or filtered. Raw backend access bypasses this selection policy.
Loopback is a machine trust boundary, not a user boundary: other local users may
access the receiver tunnel, privileged management endpoint, or raw exporter.
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
disconnecting it.** Supervised Windows attachments close their owned connection
when the receiver exits; manually attached devices require native-tool cleanup.
Shutdown closes Groupnet resources; it is
like unplugging a device, not a graceful filesystem unmount. Unexpected loss can
interrupt authentication or lose data. After any broken stream/restart, inspect
imported ports, detach stale attachments, and explicitly attach again. No silent
USB reconnect or device resurrection is attempted.

For failures, check:

1. Driver/tool installation and correct physical BUSID, without changing unrelated
   devices. No hardware or driver installation is performed by remoteusb.
2. Exporter backend availability on loopback 3240 and independent raw-port isolation.
3. Actual listener addresses and same-machine/wildcard port collisions.
4. Direct exporter address/port reachability, or optional rendezvous reachability,
   matching `network.key`, and allowlisted node IDs. In rendezvous mode, use
   `--relay-only` on both ends to separate NAT problems from authentication failures.
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
