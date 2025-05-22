use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use rsa::{
    RsaPrivateKey, RsaPublicKey, Pkcs1v15Encrypt,
    pkcs8::{EncodePublicKey, EncodePrivateKey, LineEnding},
};
use sha2::{Sha256, Digest};
use std::io::{self, Read, Write};
use std::fs::File;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum EncryptionError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    
    #[error("Encryption error: {0}")]
    Encryption(String),
    
    #[error("Decryption error: {0}")]
    Decryption(String),
    
    #[error("Key generation error: {0}")]
    KeyGeneration(String),
}

/// Generates a key from a passphrase using SHA-256
pub fn generate_key_from_passphrase(passphrase: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(passphrase.as_bytes());
    let result = hasher.finalize();
    
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// Encrypts a file using AES-256-GCM
pub fn encrypt_file(
    input_path: &Path,
    output_path: &Path,
    passphrase: &str,
) -> Result<(), EncryptionError> {
    // Generate key from passphrase
    let key_bytes = generate_key_from_passphrase(passphrase);
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    
    // Create cipher
    let cipher = Aes256Gcm::new(key);
    
    // Generate a random nonce
    let nonce_bytes = Aes256Gcm::generate_nonce(&mut OsRng);
    let nonce = Nonce::from_slice(nonce_bytes.as_slice());
    
    // Read input file
    let mut input_file = File::open(input_path)
        .map_err(|e| EncryptionError::Io(e))?;
    let mut buffer = Vec::new();
    input_file.read_to_end(&mut buffer)
        .map_err(|e| EncryptionError::Io(e))?;
    
    // Encrypt the file content
    let encrypted_data = cipher.encrypt(nonce, buffer.as_slice())
        .map_err(|e| EncryptionError::Encryption(e.to_string()))?;
    
    // Write the nonce and encrypted data to the output file
    let mut output_file = File::create(output_path)
        .map_err(|e| EncryptionError::Io(e))?;
    
    // Write nonce first (12 bytes for AES-GCM)
    output_file.write_all(nonce.as_slice())
        .map_err(|e| EncryptionError::Io(e))?;
    
    // Write encrypted data
    output_file.write_all(&encrypted_data)
        .map_err(|e| EncryptionError::Io(e))?;
    
    Ok(())
}

/// Decrypts a file using AES-256-GCM
pub fn decrypt_file(
    input_path: &Path,
    output_path: &Path,
    passphrase: &str,
) -> Result<(), EncryptionError> {
    // Generate key from passphrase
    let key_bytes = generate_key_from_passphrase(passphrase);
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    
    // Create cipher
    let cipher = Aes256Gcm::new(key);
    
    // Read input file
    let mut input_file = File::open(input_path)
        .map_err(|e| EncryptionError::Io(e))?;
    let mut buffer = Vec::new();
    input_file.read_to_end(&mut buffer)
        .map_err(|e| EncryptionError::Io(e))?;
    
    // Extract nonce (first 12 bytes)
    if buffer.len() < 12 {
        return Err(EncryptionError::Decryption("File too short".to_string()));
    }
    
    let nonce = Nonce::from_slice(&buffer[0..12]);
    let encrypted_data = &buffer[12..];
    
    // Decrypt the data
    let decrypted_data = cipher.decrypt(nonce, encrypted_data)
        .map_err(|e| EncryptionError::Decryption(e.to_string()))?;
    
    // Write decrypted data to output file
    let mut output_file = File::create(output_path)
        .map_err(|e| EncryptionError::Io(e))?;
    
    output_file.write_all(&decrypted_data)
        .map_err(|e| EncryptionError::Io(e))?;
    
    Ok(())
}

/// Generates an RSA key pair
pub fn generate_rsa_keypair() -> Result<(RsaPrivateKey, RsaPublicKey), EncryptionError> {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|e| EncryptionError::KeyGeneration(e.to_string()))?;
    let public_key = RsaPublicKey::from(&private_key);
    
    Ok((private_key, public_key))
}

/// Exports an RSA public key to PEM format
pub fn export_public_key(public_key: &RsaPublicKey) -> Result<String, EncryptionError> {
    public_key.to_public_key_pem(LineEnding::LF)
        .map_err(|e| EncryptionError::KeyGeneration(e.to_string()))
}

/// Exports an RSA private key to PEM format
pub fn export_private_key(private_key: &RsaPrivateKey) -> Result<String, EncryptionError> {
    private_key.to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| EncryptionError::KeyGeneration(e.to_string()))
        .map(|pem| pem.to_string())
}

/// Encrypts a symmetric key using RSA
pub fn encrypt_key_with_rsa(
    symmetric_key: &[u8],
    public_key: &RsaPublicKey,
) -> Result<Vec<u8>, EncryptionError> {
    let mut rng = rand::thread_rng();
    public_key.encrypt(&mut rng, Pkcs1v15Encrypt, symmetric_key)
        .map_err(|e| EncryptionError::Encryption(e.to_string()))
}

/// Decrypts a symmetric key using RSA
pub fn decrypt_key_with_rsa(
    encrypted_key: &[u8],
    private_key: &RsaPrivateKey,
) -> Result<Vec<u8>, EncryptionError> {
    private_key.decrypt(Pkcs1v15Encrypt, encrypted_key)
        .map_err(|e| EncryptionError::Decryption(e.to_string()))
}
