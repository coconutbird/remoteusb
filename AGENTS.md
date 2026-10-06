# remoteusb engineering

## Scope and layers

remoteusb transports USB/IP over Groupnet authenticated ordered streams, using
keyed TCP rendezvous, TCP hole punching and relay fallback. Existing OS drivers
export USB devices and emulate the receiving host controller; this repository
does not install drivers, change firewall rules, or weaken driver signing.

- `remoteusb-transport`: Groupnet identity/admission, keyed rendezvous and bounded
  asynchronous byte forwarding.
- `remoteusb-cli`: credentials, argument validation, listener setup and lifecycle.

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
- Share dependency versions at the workspace root; inherit them in every crate.
  Do not add dependencies for functionality already served clearly by std.
- Errors carry operational context but never USB payloads or key material.

## Security invariants

- TLS 1.3 with peer authentication in both directions, `groupnet.peer` server-name
  checking and exact independently provisioned leaf-certificate pins bound to the
  configured peer node ID. Both identities need client and server EKUs.
- Keyed rendezvous and connectivity use explicit node allowlists; never use open
  admission or silently downgrade a key/authentication failure. TCP direct is
  preferred, with encrypted relay fallback; relay-only is explicit diagnostic policy.
- Complete TLS authentication, authorized node checks and the remoteusb-specific
  application marker/reply before connecting to the USB/IP backend. Groupnet owns
  end-to-end TLS: never layer a parallel direct TLS socket mode over the fabric.
- Plaintext receiving listeners and exporting backend addresses are loopback-only.
  This is a host trust boundary, not isolation from other local users.
- Admission limits cover establishing and established Groupnet sessions, per-peer
  and node-wide, as well as local forwarding tasks. Setup deadlines do not become
  idle timeouts for attached USB devices; Groupnet reliability heartbeats remain
  active. Each local TCP connection owns one independent ordered stream.
- Every authorized certificate grants access to every device exported by the
  selected backend. Do not claim per-device authorization or payload inspection.
- No silent USB/IP stream reconnect: a broken stream requires explicit OS-level
  detach/attach. Individual failed sessions leave the daemon running; actual
  fabric closure must terminate it rather than leave a useless plaintext listener.
- Shutdown drops connections. Document this as unplugging a device, not a graceful
  filesystem unmount. Never install drivers or alter devices in automated tests.

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
