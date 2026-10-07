use std::collections::BTreeSet;
use std::io;
use std::net::SocketAddr;

use super::{port, validate_busid};

/// Parse the released usbip-win2 `port` producer, not Linux output or substrings.
/// Empty successful output is the producer's zero-device case. Unknown or
/// incomplete records must never be interpreted as absence of the owned endpoint.
pub(super) fn endpoint_present(
    output: &[u8],
    address: SocketAddr,
    busid: &str,
) -> io::Result<bool> {
    let text = std::str::from_utf8(output).map_err(|_| invalid("non-UTF8 USB/IP port status"))?;
    if text.is_empty() {
        return Ok(false);
    }
    if !text.ends_with('\n') {
        return Err(invalid("truncated USB/IP port status"));
    }
    let mut lines = text.lines();
    if lines.next() != Some("Imported USB devices") || lines.next() != Some("====================")
    {
        return Err(invalid("unknown USB/IP port status header"));
    }
    let expected = format!("usbip://{}:{}/{}", address.ip(), address.port(), busid);
    let mut found = false;
    let mut ports = BTreeSet::new();
    while let Some(line) = lines.next() {
        let entry = line
            .strip_prefix("Port ")
            .ok_or_else(|| invalid("unknown USB/IP port record"))?;
        let (number, speed) = entry
            .split_once(": device in use at ")
            .ok_or_else(|| invalid("invalid USB/IP port record"))?;
        if !decimal(number) {
            return Err(invalid("invalid USB/IP port number"));
        }
        let number = port(number.as_bytes())?;
        if speed.is_empty() || !ports.insert(number) {
            return Err(invalid("ambiguous USB/IP port record"));
        }
        let product = lines
            .next()
            .ok_or_else(|| invalid("missing USB/IP product record"))?;
        if !product.starts_with("         ") {
            return Err(invalid("invalid USB/IP product record"));
        }
        let location = lines
            .next()
            .and_then(|line| line.strip_prefix("           -> "))
            .ok_or_else(|| invalid("missing USB/IP endpoint record"))?;
        validate_location(location)?;
        found |= location == expected;
        let remote = lines
            .next()
            .and_then(|line| line.strip_prefix("           -> remote bus/dev: "))
            .ok_or_else(|| invalid("missing USB/IP bus/device record"))?;
        let (bus, device) = remote
            .split_once('/')
            .ok_or_else(|| invalid("invalid USB/IP bus/device record"))?;
        if !decimal(bus) || !decimal(device) {
            return Err(invalid("invalid USB/IP bus/device number"));
        }
        if lines
            .next()
            .and_then(|line| line.strip_prefix("           -> serial: "))
            .is_none()
        {
            return Err(invalid("missing USB/IP serial record"));
        }
        if lines
            .next()
            .and_then(|line| line.strip_prefix("           -> mode: "))
            .is_none_or(str::is_empty)
        {
            return Err(invalid("missing USB/IP receive-mode record"));
        }
    }
    if ports.is_empty() {
        return Err(invalid("USB/IP port header without complete records"));
    }
    Ok(found)
}

fn validate_location(location: &str) -> io::Result<()> {
    let endpoint = location
        .strip_prefix("usbip://")
        .ok_or_else(|| invalid("unknown USB/IP endpoint URI"))?;
    let (authority, busid) = endpoint
        .rsplit_once('/')
        .ok_or_else(|| invalid("invalid USB/IP endpoint URI"))?;
    validate_busid(busid)?;
    let (host, service) = authority
        .rsplit_once(':')
        .ok_or_else(|| invalid("invalid USB/IP endpoint service"))?;
    if host.is_empty()
        || !decimal(service)
        || service
            .parse::<u16>()
            .ok()
            .is_none_or(|service| service == 0)
    {
        return Err(invalid("invalid USB/IP endpoint host/service"));
    }
    Ok(())
}

fn decimal(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())
}

/// Positive cancellation acknowledges the teardown-created retry request. A
/// successful command with zero requests does not fence a later retry insertion.
pub(super) fn stopped_count(stderr: &[u8]) -> io::Result<u32> {
    let text = std::str::from_utf8(stderr)
        .map_err(|_| invalid("non-UTF8 USB/IP retry cancellation response"))?;
    if !text.ends_with('\n') {
        return Err(invalid("truncated USB/IP retry cancellation response"));
    }
    let mut count = None;
    for line in text.lines() {
        if let Some(value) = line
            .strip_prefix("debug: ")
            .and_then(|line| line.strip_suffix(" request(s) stopped"))
        {
            if count.is_some() || !decimal(value) {
                return Err(invalid("ambiguous USB/IP retry cancellation count"));
            }
            count = Some(
                value
                    .parse::<u32>()
                    .map_err(|_| invalid("invalid USB/IP retry cancellation count"))?,
            );
        }
    }
    count.ok_or_else(|| invalid("USB/IP client did not acknowledge retry cancellation count"))
}

fn invalid(detail: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, detail)
}

#[cfg(test)]
mod tests {
    use super::{endpoint_present, stopped_count};

    fn record(host: &str, service: u16, busid: &str) -> String {
        format!(
            "Imported USB devices\n====================\nPort 01: device in use at high-speed\n         Device description\n           -> usbip://{host}:{service}/{busid}\n           -> remote bus/dev: 001/002\n           -> serial: \n           -> mode: IRP\n"
        )
    }

    #[test]
    fn released_port_output_selects_exact_private_endpoint_and_busid() {
        let address = "127.0.0.1:1234".parse().unwrap();
        let output = record("127.0.0.1", 1234, "1-2");
        assert!(endpoint_present(output.as_bytes(), address, "1-2").unwrap());
        assert!(!endpoint_present(output.as_bytes(), address, "1-20").unwrap());
        assert!(
            !endpoint_present(output.as_bytes(), "127.0.0.1:123".parse().unwrap(), "1-2").unwrap()
        );
        assert!(endpoint_present(output.replace('\n', "\r\n").as_bytes(), address, "1-2").unwrap());
        let output = record("::1", 1234, "1-2");
        assert!(endpoint_present(output.as_bytes(), "[::1]:1234".parse().unwrap(), "1-2").unwrap());
        assert!(!endpoint_present(b"", address, "1-2").unwrap());
    }

    #[test]
    fn incomplete_or_unknown_status_cannot_prove_absence() {
        let address = "127.0.0.1:1234".parse().unwrap();
        let valid = record("127.0.0.1", 1234, "1-2");
        for invalid in [
            "warning: could not query\n",
            "Imported USB devices\n====================\n",
            valid.trim_end(),
        ] {
            assert!(endpoint_present(invalid.as_bytes(), address, "1-2").is_err());
        }
        assert!(
            endpoint_present(
                valid.replace("-> usbip://", "-> unknown://").as_bytes(),
                address,
                "1-2"
            )
            .is_err()
        );
    }

    #[test]
    fn retry_cancellation_requires_one_complete_numeric_acknowledgment() {
        assert_eq!(
            stopped_count(b"debug: 1 request(s) stopped\r\n").unwrap(),
            1
        );
        assert_eq!(stopped_count(b"debug: 0 request(s) stopped\n").unwrap(), 0);
        for invalid in [
            b"".as_slice(),
            b"debug: 1 request(s) stopped",
            b"debug: +1 request(s) stopped\n",
            b"debug: 1 request(s) stopped\ndebug: 1 request(s) stopped\n",
            b"\xff\n",
        ] {
            assert!(stopped_count(invalid).is_err());
        }
    }
}
