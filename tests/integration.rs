//
// tests/integration.rs -- Integration tests for self-signed-cert
//
// These tests run the binary and verify the generated certificates using
// the openssl command-line tool, which provides authoritative validation.
//

use std::process::Command;
use tempfile::TempDir;

/// Helper to run the self-signed-cert binary with given arguments
fn run_cert_generator(args: &[&str]) -> (TempDir, std::process::Output) {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");

    let mut cmd_args = vec!["-o", temp_dir.path().to_str().unwrap()];
    cmd_args.extend(args);

    let output = Command::new(env!("CARGO_BIN_EXE_self-signed-cert"))
        .args(&cmd_args)
        .output()
        .expect("Failed to execute binary");

    (temp_dir, output)
}

/// Run openssl x509 command to get certificate text
fn get_cert_text(cert_path: &std::path::Path) -> String {
    let output = Command::new("openssl")
        .args([
            "x509",
            "-in",
            cert_path.to_str().unwrap(),
            "-noout",
            "-text",
        ])
        .output()
        .expect("Failed to run openssl x509 command");

    assert!(
        output.status.success(),
        "openssl x509 failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8_lossy(&output.stdout).to_string()
}

/// Verify a certificate against a CA certificate
fn verify_cert_chain(ca_path: &std::path::Path, cert_path: &std::path::Path) -> bool {
    let output = Command::new("openssl")
        .args([
            "verify",
            "-CAfile",
            ca_path.to_str().unwrap(),
            cert_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to run openssl verify command");

    output.status.success()
}

// ============================================================================
// Integration Tests
// ============================================================================

#[test]
fn test_basic_certificate_generation() {
    let (temp_dir, output) = run_cert_generator(&[]);

    assert!(
        output.status.success(),
        "Binary failed with stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Check all expected files exist
    assert!(
        temp_dir.path().join("ca-key.pem").exists(),
        "ca-key.pem not created"
    );
    assert!(
        temp_dir.path().join("ca-cert.pem").exists(),
        "ca-cert.pem not created"
    );
    assert!(
        temp_dir.path().join("server-key.pem").exists(),
        "server-key.pem not created"
    );
    assert!(
        temp_dir.path().join("server-cert.pem").exists(),
        "server-cert.pem not created"
    );
}

#[test]
fn test_server_cert_has_extended_key_usage_server_auth() {
    let (temp_dir, output) = run_cert_generator(&[]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let cert_path = temp_dir.path().join("server-cert.pem");
    let cert_text = get_cert_text(&cert_path);

    // Check for extendedKeyUsage extension
    assert!(
        cert_text.contains("X509v3 Extended Key Usage"),
        "Server certificate must have X509v3 Extended Key Usage extension.\nCertificate:\n{}",
        cert_text
    );

    // Check for serverAuth (TLS Web Server Authentication)
    assert!(
        cert_text.contains("TLS Web Server Authentication"),
        "Server certificate must have TLS Web Server Authentication in extendedKeyUsage.\nCertificate:\n{}",
        cert_text
    );
}

#[test]
fn test_ca_cert_has_ca_constraint() {
    let (temp_dir, output) = run_cert_generator(&[]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let cert_path = temp_dir.path().join("ca-cert.pem");
    let cert_text = get_cert_text(&cert_path);

    // Check for basicConstraints with CA:TRUE
    assert!(
        cert_text.contains("CA:TRUE"),
        "CA certificate must have CA:TRUE in basicConstraints.\nCertificate:\n{}",
        cert_text
    );
}

#[test]
fn test_ca_cert_has_key_usage() {
    let (temp_dir, output) = run_cert_generator(&[]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let cert_path = temp_dir.path().join("ca-cert.pem");
    let cert_text = get_cert_text(&cert_path);

    // Check for keyUsage extension (should be critical for CA certs per RFC 5280)
    assert!(
        cert_text.contains("X509v3 Key Usage: critical"),
        "CA certificate must have critical keyUsage extension.\nCertificate:\n{}",
        cert_text
    );

    // Check for Certificate Sign permission
    assert!(
        cert_text.contains("Certificate Sign"),
        "CA certificate must have Certificate Sign in keyUsage.\nCertificate:\n{}",
        cert_text
    );

    // Check for CRL Sign permission
    assert!(
        cert_text.contains("CRL Sign"),
        "CA certificate must have CRL Sign in keyUsage.\nCertificate:\n{}",
        cert_text
    );
}

#[test]
fn test_server_cert_signed_by_ca() {
    let (temp_dir, output) = run_cert_generator(&[]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let ca_path = temp_dir.path().join("ca-cert.pem");
    let server_path = temp_dir.path().join("server-cert.pem");

    assert!(
        verify_cert_chain(&ca_path, &server_path),
        "Server certificate must be verifiable against CA certificate"
    );
}

#[test]
fn test_server_cert_has_subject_alt_name() {
    let (temp_dir, output) = run_cert_generator(&[]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let cert_path = temp_dir.path().join("server-cert.pem");
    let cert_text = get_cert_text(&cert_path);

    // Check for Subject Alternative Name extension
    assert!(
        cert_text.contains("X509v3 Subject Alternative Name"),
        "Server certificate must have Subject Alternative Name extension.\nCertificate:\n{}",
        cert_text
    );

    // Default common name is 127.0.0.1
    assert!(
        cert_text.contains("127.0.0.1"),
        "Server certificate SAN should contain the common name.\nCertificate:\n{}",
        cert_text
    );
}

#[test]
fn test_server_cert_has_key_usage() {
    let (temp_dir, output) = run_cert_generator(&[]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let cert_path = temp_dir.path().join("server-cert.pem");
    let cert_text = get_cert_text(&cert_path);

    // Check for keyUsage extension marked critical (per RFC 5280)
    assert!(
        cert_text.contains("X509v3 Key Usage: critical"),
        "Server certificate must have critical keyUsage extension.\nCertificate:\n{}",
        cert_text
    );

    // Check for expected keyUsage values
    assert!(
        cert_text.contains("Digital Signature"),
        "Server certificate must have Digital Signature in keyUsage.\nCertificate:\n{}",
        cert_text
    );
    assert!(
        cert_text.contains("Key Encipherment"),
        "Server certificate must have Key Encipherment in keyUsage.\nCertificate:\n{}",
        cert_text
    );
}

#[test]
fn test_custom_common_name() {
    let (temp_dir, output) = run_cert_generator(&["--common-name", "example.local"]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let cert_path = temp_dir.path().join("server-cert.pem");
    let cert_text = get_cert_text(&cert_path);

    // Check that custom common name appears in the certificate
    assert!(
        cert_text.contains("CN=example.local") || cert_text.contains("CN = example.local"),
        "Server certificate should have custom common name.\nCertificate:\n{}",
        cert_text
    );
}

#[test]
fn test_keys_are_valid_pem() {
    let (temp_dir, output) = run_cert_generator(&[]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify CA key is valid
    let ca_key_check = Command::new("openssl")
        .args([
            "rsa",
            "-in",
            temp_dir.path().join("ca-key.pem").to_str().unwrap(),
            "-check",
            "-noout",
        ])
        .output()
        .expect("Failed to run openssl rsa command");

    assert!(
        ca_key_check.status.success(),
        "CA key should be valid RSA key: {}",
        String::from_utf8_lossy(&ca_key_check.stderr)
    );

    // Verify server key is valid
    let server_key_check = Command::new("openssl")
        .args([
            "rsa",
            "-in",
            temp_dir.path().join("server-key.pem").to_str().unwrap(),
            "-check",
            "-noout",
        ])
        .output()
        .expect("Failed to run openssl rsa command");

    assert!(
        server_key_check.status.success(),
        "Server key should be valid RSA key: {}",
        String::from_utf8_lossy(&server_key_check.stderr)
    );
}

#[test]
fn test_csr_output_when_requested() {
    let (temp_dir, output) = run_cert_generator(&["--csr-out", "server-csr.pem"]);
    assert!(
        output.status.success(),
        "Binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let csr_path = temp_dir.path().join("server-csr.pem");
    assert!(
        csr_path.exists(),
        "CSR file should be created when requested"
    );

    // Verify CSR is valid
    let csr_check = Command::new("openssl")
        .args([
            "req",
            "-in",
            csr_path.to_str().unwrap(),
            "-noout",
            "-verify",
        ])
        .output()
        .expect("Failed to run openssl req command");

    assert!(
        csr_check.status.success(),
        "CSR should be valid: {}",
        String::from_utf8_lossy(&csr_check.stderr)
    );
}
