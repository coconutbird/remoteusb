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
fn endpoint_defaults_and_aliases_keep_fixed_certificate_roles() -> Result<(), clap::Error> {
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
        "--candidate-bind",
        "127.0.0.1:0",
        "--candidate-bind",
        "127.0.0.2:0",
        "--relay-only",
    ])?;
    let Command::Serve(args) = cli.command else {
        panic!("expected serve command");
    };
    let config = args.common.peer_config(args.local_id, args.peer_id, true);
    assert_eq!(config.local_id, "key-pc");
    assert_eq!(config.peer_id, "work-pc");
    assert!(config.cert.ends_with("exporter.pem"));
    assert!(config.key.ends_with("exporter.key"));
    assert!(config.peer_cert.ends_with("receiver.pem"));
    assert_eq!(config.candidate_binds.len(), 2);
    assert!(config.relay_only);

    let cli = Cli::try_parse_from([
        "remoteusb",
        "connect",
        "--credentials",
        "identities",
        "--rendezvous",
        "127.0.0.1:7443",
    ])?;
    let Command::Connect(args) = cli.command else {
        panic!("expected connect command");
    };
    let config = args.common.peer_config(args.local_id, args.peer_id, false);
    assert_eq!(config.local_id, "receiver");
    assert_eq!(config.peer_id, "exporter");
    assert!(config.cert.ends_with("receiver.pem"));
    assert!(config.peer_cert.ends_with("exporter.pem"));
    assert_eq!(
        config.candidate_binds,
        vec!["0.0.0.0:0".parse().expect("literal address")]
    );
    assert!(!config.relay_only);
    assert_eq!(config.limits.max_connections, 64);
    assert_eq!(config.limits.connect_timeout.as_secs(), 10);
    Ok(())
}

#[test]
fn cli_rejects_missing_rendezvous_zero_limits_and_legacy_flags() {
    assert!(Cli::try_parse_from(["remoteusb", "serve", "--credentials", "identities"]).is_err());
    for arguments in [
        ["--max-connections", "0"],
        ["--connect-timeout-secs", "0"],
        ["--remote", "127.0.0.1:7443"],
        ["--server-name", "groupnet.peer"],
        ["--ca", "ca.pem"],
        ["--insecure", "true"],
    ] {
        let mut command = vec![
            "remoteusb",
            "connect",
            "--credentials",
            "identities",
            "--rendezvous",
            "127.0.0.1:7443",
        ];
        command.extend(arguments);
        assert!(Cli::try_parse_from(command).is_err());
    }
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
