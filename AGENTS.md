# remoteusb engineering

## Scope and layers

remoteusb transports USB/IP over Groupnet authenticated ordered streams, using
direct TCP by default and optional keyed rendezvous, hole punching and relay.
Existing OS drivers export devices and emulate the receiving host controller;
this repository does not install drivers, change firewalls, or weaken signing.

- `remoteusb-transport`: Groupnet identity/admission, direct and rendezvous
  connectivity, and bounded asynchronous byte forwarding.
- `remoteusb-cli`: credentials, commands, discovery, on-demand exporter device
  sharing/policy, and receiver/supervisor lifecycle.

Dependencies point downward. Keep USB driver policy out of the transport layer.
Do not add a crate until it owns a distinct responsibility.

## Rust conventions

Inspired by docstore's workspace: Rust 2024, resolver 3, shared package metadata,
centralized dependencies with justification comments, inherited workspace lints.
The toolchain is pinned to the version used to verify this project.

- Warnings, missing public documentation, unsafe code, and Clippy pedantic are
  denied. Document public contracts and error cases.
- Prefer safe Rust, explicit ownership, small functions, and boring control flow.
- Use narrow `#[expect(..., reason = "...")]` only for a justified exception;
  never blanket `#[allow]`. An invariant is not an excuse to panic on peer input.
- Keep each function below 200 lines. Use rustfmt defaults.
- No avoidable allocation or copying in the transfer path. Keep memory bounded,
  use backpressure, and never buffer an entire peer-controlled transfer.
- Size every queue on a stream's path from the one flow policy in
  `remoteusb-transport/src/flow.rs`. Links are reliable TCP: a local drop is seen
  as loss and triggers retransmission backoff, so no queue may drop a full window.
  Changing segment size or the preamble is a wire-protocol change for both peers.
- Validate at the boundary into types (e.g. `BusId`, typed USB/IP headers) and
  keep one owner per wire format or policy. Use traits for genuine alternative
  implementations (endpoint roles, OS device hosts), not single-use indirection.
- Share dependency versions at the workspace root; inherit them in every crate.
  Do not add dependencies for functionality already served clearly by std.
- Errors carry operational context but never USB payloads or key material.

## Security invariants

- TLS 1.3 with peer authentication in both directions, `groupnet.peer` server-name
  checking and exact independently provisioned leaf-certificate pins bound to the
  configured peer node ID. Both identities need client and server EKUs.
- Direct native TCP uses an explicit node allowlist, never open admission.
  Routing claims/metadata are not authenticated identities: TLS and exact pins
  remain the USB access boundary. Never send network keys in plaintext admission.
- Optional keyed rendezvous/connectivity uses explicit node allowlists and must
  never downgrade key/authentication failures. It prefers punched direct paths
  with encrypted relay fallback; relay-only is explicit diagnostic policy.
- Complete TLS authentication, authorized node checks and the remoteusb-specific
  application marker/reply before connecting to the USB/IP backend. Groupnet owns
  end-to-end TLS: never layer a parallel direct TLS socket mode over the fabric.
- Plaintext receiving listeners and exporting backend addresses are loopback-only.
  This is a host trust boundary, not isolation from other local users.
- Admission limits cover establishing and established Groupnet sessions, per-peer
  and node-wide, as well as local forwarding tasks. Setup deadlines do not become
  idle timeouts for attached USB devices; Groupnet reliability heartbeats remain
  active. Each local TCP connection owns one independent ordered stream.
- Managed exporters expose exportable devices on demand, optionally restricted by
  BUSID. Enforce selection before binding; restore only sharing owned by the
  session and never act on a replacement device. Preserve preexisting sharing.
  All authorized peers share the exporter policy; do not claim payload filtering.
- No silent USB/IP stream reconnect. Plain tunnels/exporters survive individual
  failed sessions; fabric closure terminates them. An attachment receiver exits
  when its attached stream ends and asks its supervisor to close its owned socket.
- The independent Windows supervisor owns the driver-facing connection and retry
  cancellation. Parent lifetime is a private pipe, not a reusable PID. Never detach
  using a saved driver port, detach-all, or guess ownership after port reuse.
- Shutdown is unplugging, not a graceful filesystem unmount. Killing both owner
  and supervisor or losing power cannot run recovery. Never install drivers or
  alter devices in automated tests.

## Verification

Run `mise run ci`, or equivalently:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

Test consumer-visible boundaries: authentication, endpoint restrictions, binary
integrity, half-closes, capacity, and cancellation. Use ephemeral ports and
short bounded waits, generate test credentials, and leave no background tasks.
Do not re-pin tests to incidental wording, source layout, or forwarding mocks.
Run the actual CLI for meaningful behavior changes; tests alone do not prove
that deployed endpoints work. Distinguish loopback transport evidence from real
hardware/driver qualification. Keep README usage and security claims aligned
with implementation. Never commit certificates, private keys, or device data.
The WAN test in `remoteusb-cli/tests/wan.rs` is always real hardware: the operator
passes the device; never add a synthetic mode to it.
