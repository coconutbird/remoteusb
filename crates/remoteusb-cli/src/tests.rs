//! Credential issuance and CLI trust-boundary tests; no driver or device access.

use std::fs;
use std::io::{self, BufReader};
use std::path::Path;
use std::sync::Arc;

use clap::Parser as _;
use rustls::RootCertStore;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::ServerCertVerifier as _;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::WebPkiClientVerifier;

use super::{Cli, Command, credentials, require_loopback};

/// Parse generated PEM without accepting an empty certificate file.
fn certificate(path: &Path) -> io::Result<CertificateDer<'static>> {
    rustls_pemfile::certs(&mut BufReader::new(fs::File::open(path)?))
        .next()
        .ok_or_else(|| io::Error::other("missing certificate"))?
}

#[test]
fn generated_credentials_validate_in_both_tls_directions() -> Result<(), Box<dyn std::error::Error>>
{
    let temporary = tempfile::tempdir()?;
    let out = temporary.path().join("credentials");
    credentials::initialize(&out)?;
    let mut roots = RootCertStore::empty();
    roots.add(certificate(&out.join("ca.pem"))?)?;
    let roots = Arc::new(roots);
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server =
        WebPkiServerVerifier::builder_with_provider(roots.clone(), provider.clone()).build()?;
    let client = WebPkiClientVerifier::builder_with_provider(roots, provider).build()?;
    let name = ServerName::try_from("groupnet.peer")?;
    let wrong_name = ServerName::try_from("other.peer")?;
    for role in ["exporter", "receiver"] {
        let leaf = certificate(&out.join(format!("{role}.pem")))?;
        server.verify_server_cert(&leaf, &[], &name, &[], UnixTime::now())?;
        client.verify_client_cert(&leaf, &[], UnixTime::now())?;
        assert!(
            server
                .verify_server_cert(&leaf, &[], &wrong_name, &[], UnixTime::now())
                .is_err()
        );
        let key = rustls_pemfile::private_key(&mut BufReader::new(fs::File::open(
            out.join(format!("{role}.key")),
        )?))?
        .ok_or("missing private key")?;
        // A valid chain alone is insufficient: the generated private key must match.
        rustls::sign::CertifiedKey::from_der(
            vec![leaf],
            key,
            &rustls::crypto::ring::default_provider(),
        )?;
    }
    let key = fs::read_to_string(out.join("network.key"))?;
    let key = key.trim();
    assert_eq!(key.len(), 64);
    assert!(key.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(fs::read_dir(&out)?.count(), 6);
    assert!(!out.join("ca.key").exists());
    Ok(())
}

#[test]
fn init_refuses_existing_directory_and_preserves_contents() -> io::Result<()> {
    let temporary = tempfile::tempdir()?;
    let existing = temporary.path().join("existing");
    fs::create_dir(&existing)?;
    fs::write(existing.join("network.key"), b"do not replace")?;
    let error = credentials::initialize(&existing).expect_err("must refuse existing output");
    assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(fs::read(existing.join("network.key"))?, b"do not replace");
    let empty = temporary.path().join("empty");
    fs::create_dir(&empty)?;
    assert_eq!(
        credentials::initialize(&empty)
            .expect_err("must refuse empty output")
            .kind(),
        io::ErrorKind::AlreadyExists
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn init_creates_owner_only_directory_and_files() -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let temporary = tempfile::tempdir()?;
    let out = temporary.path().join("credentials");
    credentials::initialize(&out)?;
    assert_eq!(fs::metadata(&out)?.permissions().mode() & 0o777, 0o700);
    for entry in fs::read_dir(&out)? {
        assert_eq!(entry?.metadata()?.permissions().mode() & 0o777, 0o600);
    }
    Ok(())
}

#[test]
fn aliases_never_change_which_private_key_is_loaded() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::try_parse_from([
        "remoteusb",
        "serve",
        "--credentials",
        "identities",
        "--rendezvous",
        "127.0.0.1:7443",
        "--local-id",
        "key-pc",
        "--peer-id",
        "work-pc",
    ])?;
    let Command::Serve(args) = cli.command else {
        panic!("expected serve");
    };
    let config = args.common.config(args.peer_id, true, None)?;
    assert_eq!(config.local_id, "key-pc");
    assert_eq!(config.peer_id, "work-pc");
    assert!(config.cert.ends_with("exporter.pem"));
    assert!(config.key.ends_with("exporter.key"));
    assert!(config.peer_cert.ends_with("receiver.pem"));

    let cli = Cli::try_parse_from([
        "remoteusb",
        "connect",
        "key-pc",
        "--credentials",
        "identities",
        "--rendezvous",
        "127.0.0.1:7443",
        "--local-id",
        "work-pc",
    ])?;
    let Command::Connect(args) = cli.command else {
        panic!("expected connect");
    };
    let config = args.endpoint.config()?;
    assert_eq!(config.local_id, "work-pc");
    assert_eq!(config.peer_id, "key-pc");
    assert!(config.cert.ends_with("receiver.pem"));
    assert!(config.key.ends_with("receiver.key"));
    assert!(config.peer_cert.ends_with("exporter.pem"));
    Ok(())
}

#[test]
fn incompatible_modes_and_unbounded_limits_are_rejected() {
    for arguments in [
        vec!["connect", "192.0.2.1", "--max-connections", "0"],
        vec!["connect", "192.0.2.1", "--connect-timeout-secs", "0"],
        vec!["connect", "192.0.2.1", "--relay-only"],
        vec!["list", "192.0.2.1", "--candidate-bind", "127.0.0.1:0"],
        vec![
            "serve",
            "--listen",
            "0.0.0.0:7443",
            "--rendezvous",
            "192.0.2.1:7443",
        ],
        vec![
            "connect",
            "exporter",
            "--rendezvous",
            "192.0.2.1:7443",
            "--peer-id",
            "other",
        ],
        vec!["connect", "192.0.2.1", "--usbip", "usbip.exe"],
        vec!["connect", "192.0.2.1", "--insecure"],
        vec!["serve", "--pick", "--device", "1-2"],
        vec!["detach", "1"],
    ] {
        let mut command = vec!["remoteusb"];
        command.extend(arguments);
        assert!(Cli::try_parse_from(command).is_err());
    }
}

#[test]
fn direct_targets_are_concrete_unicast_addresses() -> io::Result<()> {
    use super::args::direct_address;
    assert_eq!(
        direct_address("192.0.2.1")?,
        "192.0.2.1:7443".parse().unwrap()
    );
    assert_eq!(direct_address("[::1]:9000")?, "[::1]:9000".parse().unwrap());
    assert_eq!(direct_address("::1")?, "[::1]:7443".parse().unwrap());
    for target in [
        "0.0.0.0",
        "::",
        "255.255.255.255",
        "224.0.0.1",
        "192.0.2.1:0",
        "exporter",
    ] {
        assert!(direct_address(target).is_err());
    }
    Ok(())
}

#[test]
fn plaintext_addresses_must_be_loopback() {
    for option in ["--backend", "--listen"] {
        assert!(
            require_loopback("127.0.0.1:3240".parse().expect("literal address"), option).is_ok()
        );
        assert!(require_loopback("[::1]:3240".parse().expect("literal address"), option).is_ok());
        assert!(
            require_loopback("0.0.0.0:3240".parse().expect("literal address"), option).is_err()
        );
        assert!(
            require_loopback("192.0.2.1:3240".parse().expect("literal address"), option).is_err()
        );
    }
}
