use rustls::ServerConfig;
use std::fs;
use std::sync::Arc;

/// Loads the TLS configuration using a certificate and private key.
/// (This is a stub—you can later integrate this into the proxy listener.)
pub fn load_tls_config() -> Arc<ServerConfig> {
    // Paths to your TLS certificate and private key.
    let certs = load_certs("cert.pem");
    let key = load_private_key("key.pem");

    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("Failed to set certificate");
    Arc::new(config)
}

/// Loads certificates from the given PEM file.
fn load_certs(path: &str) -> Vec<rustls::Certificate> {
    let certfile = fs::File::open(path).expect("Cannot open certificate file");
    let mut reader = std::io::BufReader::new(certfile);
    rustls_pemfile::certs(&mut reader)
        .unwrap()
        .into_iter()
        .map(rustls::Certificate)
        .collect()
}

/// Loads a private key from the given PEM file (expects PKCS8 format).
fn load_private_key(path: &str) -> rustls::PrivateKey {
    let keyfile = fs::File::open(path).expect("Cannot open private key file");
    let mut reader = std::io::BufReader::new(keyfile);
    let keys = rustls_pemfile::pkcs8_private_keys(&mut reader).unwrap();
    if !keys.is_empty() {
        return rustls::PrivateKey(keys[0].clone());
    }
    panic!("No private keys found in {}", path);
} 