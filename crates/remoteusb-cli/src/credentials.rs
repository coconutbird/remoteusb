//! New-directory-only credential provisioning for the two endpoint roles.

use std::fs::{DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};

/// Create a directory without following or replacing an existing output entry.
fn create_directory(out: &Path) -> io::Result<()> {
    #[cfg(not(unix))]
    let builder = DirBuilder::new();
    #[cfg(unix)]
    let mut builder = DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(out).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "cannot create new credentials directory {}: {error}",
                out.display()
            ),
        )
    })
}

/// Write a newly created file; never truncate an existing file or follow a symlink.
fn write_new(out: &Path, name: &str, contents: &[u8]) -> io::Result<()> {
    let path = out.join(name);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("cannot create {}: {error}", path.display()),
        )
    })?;
    file.write_all(contents)?;
    file.sync_all()
}

/// Generate a Groupnet TLS leaf accepted in either TLS handshake direction.
fn issue_endpoint(out: &Path, role: &str, ca: &CertifiedIssuer<'_, KeyPair>) -> io::Result<()> {
    let mut params =
        CertificateParams::new(vec!["groupnet.peer".to_owned()]).map_err(io::Error::other)?;
    params.distinguished_name = distinguished_name(&format!("remoteusb {role}"));
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let key = KeyPair::generate().map_err(io::Error::other)?;
    let leaf = params.signed_by(&key, ca).map_err(io::Error::other)?;
    write_new(out, &format!("{role}.pem"), leaf.pem().as_bytes())?;
    write_new(out, &format!("{role}.key"), key.serialize_pem().as_bytes())
}

/// Use explicit names without including secrets or user-selected routing names.
fn distinguished_name(common_name: &str) -> DistinguishedName {
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, common_name);
    name
}

/// Encode a cryptographically random, 32-byte rendezvous key as 64 hex digits.
fn network_key() -> io::Result<[u8; 65]> {
    let mut random = [0_u8; 32];
    getrandom::fill(&mut random)
        .map_err(|_| io::Error::other("secure randomness unavailable for network key"))?;
    let alphabet = b"0123456789abcdef";
    let mut encoded = [b'\n'; 65];
    for (pair, byte) in encoded[..64].as_chunks_mut::<2>().0.iter_mut().zip(random) {
        pair[0] = alphabet[usize::from(byte >> 4)];
        pair[1] = alphabet[usize::from(byte & 0x0f)];
    }
    Ok(encoded)
}

/// Provision credentials, retaining only the CA public certificate on disk.
///
/// An error after directory creation can leave partial output. Such a directory
/// is never reused; inspect it and select a fresh output directory on retry.
/// Windows permissions inherit from the parent; restrict that ACL before init.
pub(super) fn initialize(out: &Path) -> io::Result<()> {
    create_directory(out)?;
    let network_key = network_key()?;
    let mut params = CertificateParams::new(Vec::<String>::new()).map_err(io::Error::other)?;
    params.distinguished_name = distinguished_name("remoteusb private CA");
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca = CertifiedIssuer::self_signed(params, KeyPair::generate().map_err(io::Error::other)?)
        .map_err(io::Error::other)?;
    write_new(out, "ca.pem", ca.pem().as_bytes())?;
    issue_endpoint(out, "exporter", &ca)?;
    issue_endpoint(out, "receiver", &ca)?;
    write_new(out, "network.key", &network_key)?;

    println!("Created credentials in {}", out.display());
    println!("Public certificates: ca.pem, exporter.pem, receiver.pem");
    println!("Secrets: exporter.key, receiver.key, network.key (protect file access)");
    println!("The CA signing key was not saved. See README for restricted file distribution.");
    println!("Next commands (replace RENDEZVOUS-IP with a reachable numeric IP):");
    println!(
        "  remoteusb rendezvous --listen 0.0.0.0:7443 --credentials \"{}\"",
        out.display()
    );
    println!(
        "  remoteusb serve --backend 127.0.0.1:3240 --rendezvous RENDEZVOUS-IP:7443 --credentials \"{}\"",
        out.display()
    );
    println!(
        "  remoteusb connect --listen 127.0.0.1:3240 --rendezvous RENDEZVOUS-IP:7443 --credentials \"{}\"",
        out.display()
    );
    Ok(())
}
