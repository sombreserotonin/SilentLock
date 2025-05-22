use std::path::{Path, PathBuf};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use uuid::Uuid;
use log::{error, warn};
use crate::models::FileInfo;

/// Sanitizes a filename to prevent directory traversal and other security issues
pub fn sanitize_filename(filename: &str) -> String {
    // Remove any path components
    let filename = Path::new(filename)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("unknown_file");
    
    // Replace any potentially problematic characters
    let filename = filename
        .replace('/', "_")
        .replace('\\', "_")
        .replace(':', "_")
        .replace('*', "_")
        .replace('?', "_")
        .replace('"', "_")
        .replace('<', "_")
        .replace('>', "_")
        .replace('|', "_");
    
    filename.to_string()
}

/// Generates a unique filename for storing uploaded files
pub fn generate_unique_filename(original_filename: &str) -> String {
    let sanitized = sanitize_filename(original_filename);
    let uuid = Uuid::new_v4();
    
    // Extract extension if present
    let ext = Path::new(&sanitized)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("");
    
    if ext.is_empty() {
        format!("{}", uuid)
    } else {
        format!("{}.{}", uuid, ext)
    }
}

/// Gets the path for storing an uploaded file
pub fn get_upload_path(filename: &str) -> PathBuf {
    let unique_filename = generate_unique_filename(filename);
    PathBuf::from("./data/uploads").join(unique_filename)
}

/// Gets the path for storing an encrypted file
pub fn get_encrypted_path(filename: &str) -> PathBuf {
    let unique_filename = generate_unique_filename(filename);
    PathBuf::from("./data/encrypted").join(unique_filename)
}

/// Validates a file size to ensure it's within acceptable limits
pub fn validate_file_size(size: u64) -> bool {
    // Limit file size to 100MB
    const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024;
    size <= MAX_FILE_SIZE
}

/// Validates a file's content type
pub fn validate_content_type(content_type: &str) -> bool {
    // This is a basic implementation
    // In a production environment, you might want to be more specific
    // about which content types are allowed
    !content_type.contains("application/x-msdownload") &&
    !content_type.contains("application/x-msdos-program") &&
    !content_type.contains("application/x-msdos-windows") &&
    !content_type.contains("application/x-download")
}

/// Saves an in-memory file to disk
pub fn save_file_to_disk(
    data: &[u8],
    path: &Path,
) -> io::Result<()> {
    // Create parent directories if they don't exist
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    
    // Write the file
    let mut file = File::create(path)?;
    file.write_all(data)?;
    
    Ok(())
}

/// In-memory storage for file information
/// In a production environment, this would be replaced with a database
pub struct FileStore {
    files: std::sync::RwLock<Vec<FileInfo>>,
}

impl FileStore {
    pub fn new() -> Self {
        Self {
            files: std::sync::RwLock::new(Vec::new()),
        }
    }
    
    pub fn add_file(&self, file_info: FileInfo) {
        let mut files = self.files.write().unwrap();
        files.push(file_info);
    }
    
    pub fn get_file(&self, id: &str) -> Option<FileInfo> {
        let files = self.files.read().unwrap();
        files.iter().find(|f| f.id == id).cloned()
    }
    
    pub fn list_files(&self) -> Vec<FileInfo> {
        let files = self.files.read().unwrap();
        files.clone()
    }
    
    pub fn remove_file(&self, id: &str) {
        let mut files = self.files.write().unwrap();
        if let Some(pos) = files.iter().position(|f| f.id == id) {
            files.remove(pos);
        }
    }
}

impl Default for FileStore {
    fn default() -> Self {
        Self::new()
    }
}
