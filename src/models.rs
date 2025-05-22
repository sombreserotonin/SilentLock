use serde::{Serialize, Deserialize};
use uuid::Uuid;
use std::path::PathBuf;

/// Represents a file in the system
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileInfo {
    /// Unique identifier for the file
    pub id: String,
    
    /// Original filename
    pub filename: String,
    
    /// Size of the file in bytes
    pub size: u64,
    
    /// MIME type of the file
    pub content_type: Option<String>,
    
    /// Whether the file is encrypted
    pub encrypted: bool,
    
    /// Timestamp when the file was uploaded
    pub uploaded_at: chrono::DateTime<chrono::Utc>,
    
    /// Path to the file on disk (not exposed to clients)
    #[serde(skip_serializing)]
    pub path: PathBuf,
}

impl FileInfo {
    /// Creates a new FileInfo instance for an uploaded file
    pub fn new(filename: String, size: u64, content_type: Option<String>, path: PathBuf) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            filename,
            size,
            content_type,
            encrypted: false,
            uploaded_at: chrono::Utc::now(),
            path,
        }
    }
    
    /// Creates a new FileInfo instance for an encrypted file
    pub fn new_encrypted(
        original: &FileInfo,
        encrypted_path: PathBuf,
        encrypted_size: u64,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            filename: format!("{}.encrypted", original.filename),
            size: encrypted_size,
            content_type: Some("application/octet-stream".to_string()),
            encrypted: true,
            uploaded_at: chrono::Utc::now(),
            path: encrypted_path,
        }
    }
}

/// Request to encrypt a file
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptRequest {
    /// ID of the file to encrypt
    pub file_id: String,
    
    /// Passphrase to use for encryption
    pub passphrase: String,
}

/// Request to decrypt a file
#[derive(Debug, Serialize, Deserialize)]
pub struct DecryptRequest {
    /// ID of the file to decrypt
    pub file_id: String,
    
    /// Passphrase to use for decryption
    pub passphrase: String,
}

/// Response for file operations
#[derive(Debug, Serialize, Deserialize)]
pub struct FileResponse {
    /// Success status
    pub success: bool,
    
    /// Message describing the result
    pub message: String,
    
    /// File information if available
    pub file: Option<FileInfo>,
}

/// Response for listing files
#[derive(Debug, Serialize, Deserialize)]
pub struct ListFilesResponse {
    /// List of files
    pub files: Vec<FileInfo>,
}

/// Request to upload a file with encryption
#[derive(Debug, Serialize, Deserialize)]
pub struct UploadEncryptRequest {
    /// Passphrase to use for encryption
    pub passphrase: String,
}
