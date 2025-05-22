use actix_web::{web, HttpResponse, Error, error, Result, http::header};
use actix_multipart::Multipart;
use futures::{StreamExt, TryStreamExt};
use std::io::{Read, Write};
use std::path::Path;
use std::fs;
use log::{info, error, warn};
use uuid::Uuid;

use crate::models::{FileInfo, FileResponse, ListFilesResponse, EncryptRequest, DecryptRequest, UploadEncryptRequest};
use crate::utils::{FileStore, get_upload_path, get_encrypted_path, validate_file_size, validate_content_type, save_file_to_disk};
use crate::encryption::{encrypt_file as encrypt_file_util, decrypt_file as decrypt_file_util, EncryptionError};

/// Handle file upload
pub async fn upload_file(
    mut payload: Multipart,
    file_store: web::Data<FileStore>,
) -> Result<HttpResponse, Error> {
    // Process multipart form data
    while let Ok(Some(mut field)) = payload.try_next().await {
        let content_disposition = field.content_disposition();
        
        // Get filename from the Content-Disposition header
        let filename = content_disposition
            .get_filename()
            .map(|s| s.to_owned())
            .ok_or_else(|| error::ErrorBadRequest("No filename provided"))?;
        
        // Get content type
        let content_type = field
            .content_type()
            .map(|ct| ct.to_string());
        
        // Validate content type if available
        if let Some(ct) = &content_type {
            if !validate_content_type(ct) {
                return Err(error::ErrorBadRequest("Invalid content type"));
            }
        }
        
        // Generate a path for the uploaded file
        let file_path = get_upload_path(&filename);
        
        // Create a buffer to store the file
        let mut data = Vec::new();
        
        // Read the field data
        while let Some(chunk) = field.next().await {
            let chunk = chunk.map_err(|e| {
                error!("Error reading multipart chunk: {}", e);
                error::ErrorInternalServerError("Error reading file data")
            })?;
            
            // Check file size limit while reading
            data.extend_from_slice(&chunk);
            if !validate_file_size(data.len() as u64) {
                return Err(error::ErrorBadRequest("File too large"));
            }
        }
        
        // Save the file to disk
        save_file_to_disk(&data, &file_path).map_err(|e| {
            error!("Error saving file: {}", e);
            error::ErrorInternalServerError("Error saving file")
        })?;
        
        // Create file info
        let file_info = FileInfo::new(
            filename,
            data.len() as u64,
            content_type,
            file_path,
        );
        
        // Store file info
        file_store.add_file(file_info.clone());
        
        info!("File uploaded: {}", file_info.id);
        
        // Return success response
        return Ok(HttpResponse::Ok().json(FileResponse {
            success: true,
            message: "File uploaded successfully".to_string(),
            file: Some(file_info),
        }));
    }
    
    // If we get here, no file was uploaded
    Err(error::ErrorBadRequest("No file uploaded"))
}

/// Handle file encryption
pub async fn encrypt_file(
    req: web::Json<EncryptRequest>,
    file_store: web::Data<FileStore>,
) -> Result<HttpResponse, Error> {
    // Get the file to encrypt
    let file_info = match file_store.get_file(&req.file_id) {
        Some(file) => file,
        None => return Err(error::ErrorNotFound("File not found")),
    };
    
    // Check if the file is already encrypted
    if file_info.encrypted {
        return Err(error::ErrorBadRequest("File is already encrypted"));
    }
    
    // Generate a path for the encrypted file
    let encrypted_path = get_encrypted_path(&format!("{}.encrypted", file_info.filename));
    
    // Encrypt the file
    match encrypt_file_util(
        &file_info.path,
        &encrypted_path,
        &req.passphrase,
    ) {
        Ok(_) => {
            // Get the size of the encrypted file
            let encrypted_size = fs::metadata(&encrypted_path)
                .map(|m| m.len())
                .unwrap_or(0);
            
            // Create file info for the encrypted file
            let encrypted_file_info = FileInfo::new_encrypted(
                &file_info,
                encrypted_path,
                encrypted_size,
            );
            
            // Store file info
            file_store.add_file(encrypted_file_info.clone());
            
            info!("File encrypted: {}", encrypted_file_info.id);
            
            // Delete the original file
            if let Err(e) = fs::remove_file(&file_info.path) {
                warn!("Failed to delete original file after encryption: {}", e);
                // Continue even if deletion fails
            } else {
                info!("Original file deleted after encryption: {}", file_info.id);
                // Remove the original file from the file store
                file_store.remove_file(&file_info.id);
            }
            
            // Return success response
            Ok(HttpResponse::Ok().json(FileResponse {
                success: true,
                message: "File encrypted successfully and original file deleted".to_string(),
                file: Some(encrypted_file_info),
            }))
        },
        Err(e) => {
            error!("Error encrypting file: {:?}", e);
            Err(error::ErrorInternalServerError("Error encrypting file"))
        }
    }
}

/// Handle file decryption
pub async fn decrypt_file(
    req: web::Json<DecryptRequest>,
    form: Option<web::Form<DecryptRequest>>,
    file_store: web::Data<FileStore>,
) -> Result<HttpResponse, Error> {
    // Get the request data from either JSON or form data
    let request = if let Some(form_data) = form {
        form_data.into_inner()
    } else {
        req.into_inner()
    };
    
    // Get the file to decrypt
    let file_info = match file_store.get_file(&request.file_id) {
        Some(file) => file,
        None => return Err(error::ErrorNotFound("File not found")),
    };
    
    // Check if the file is encrypted
    if !file_info.encrypted {
        return Err(error::ErrorBadRequest("File is not encrypted"));
    }
    
    // Generate a temporary path for the decrypted file
    let decrypted_filename = file_info.filename.replace(".encrypted", "");
    let temp_decrypted_path = get_upload_path(&format!("temp_decrypted_{}", decrypted_filename));
    
    // Decrypt the file to a temporary location
    match decrypt_file_util(
        &file_info.path,
        &temp_decrypted_path,
        &request.passphrase,
    ) {
        Ok(_) => {
            // Read the decrypted file
            let mut file = match fs::File::open(&temp_decrypted_path) {
                Ok(file) => file,
                Err(e) => {
                    error!("Error opening decrypted file: {}", e);
                    return Err(error::ErrorInternalServerError("Error opening decrypted file"));
                }
            };
            
            // Read file content into a buffer
            let mut buffer = Vec::new();
            if let Err(e) = file.read_to_end(&mut buffer) {
                error!("Error reading decrypted file: {}", e);
                return Err(error::ErrorInternalServerError("Error reading decrypted file"));
            }
            
            // Close the file handle
            drop(file);
            
            // Delete the temporary decrypted file
            if let Err(e) = fs::remove_file(&temp_decrypted_path) {
                warn!("Failed to delete temporary decrypted file: {}", e);
                // Continue even if deletion fails
            }
            
            info!("File decrypted and ready for download: {}", file_info.id);
            
            // Determine content type (use a generic one if not known)
            let content_type = "application/octet-stream".to_string();
            
            // Return the file as a download
            Ok(HttpResponse::Ok()
                .content_type(content_type)
                .append_header((
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"{}\"", decrypted_filename),
                ))
                .body(buffer))
        },
        Err(e) => {
            match e {
                EncryptionError::Decryption(_) => {
                    warn!("Decryption failed, possibly wrong passphrase: {:?}", e);
                    Err(error::ErrorBadRequest("Decryption failed, possibly wrong passphrase"))
                },
                _ => {
                    error!("Error decrypting file: {:?}", e);
                    Err(error::ErrorInternalServerError("Error decrypting file"))
                }
            }
        }
    }
}

/// List all files
pub async fn list_files(
    file_store: web::Data<FileStore>,
) -> Result<HttpResponse, Error> {
    let files = file_store.list_files();
    
    Ok(HttpResponse::Ok().json(ListFilesResponse {
        files,
    }))
}

/// Upload a file with encryption
pub async fn upload_encrypt_file(
    mut payload: Multipart,
    encrypt_req: web::Query<UploadEncryptRequest>,
    file_store: web::Data<FileStore>,
) -> Result<HttpResponse, Error> {
    // Process multipart form data
    while let Ok(Some(mut field)) = payload.try_next().await {
        let content_disposition = field.content_disposition();
        
        // Get filename from the Content-Disposition header
        let filename = content_disposition
            .get_filename()
            .map(|s| s.to_owned())
            .ok_or_else(|| error::ErrorBadRequest("No filename provided"))?;
        
        // Get content type
        let content_type = field
            .content_type()
            .map(|ct| ct.to_string());
        
        // Validate content type if available
        if let Some(ct) = &content_type {
            if !validate_content_type(ct) {
                return Err(error::ErrorBadRequest("Invalid content type"));
            }
        }
        
        // Generate a path for the uploaded file (temporary)
        let temp_path = get_upload_path(&format!("temp_{}", &filename));
        
        // Create a buffer to store the file
        let mut data = Vec::new();
        
        // Read the field data
        while let Some(chunk) = field.next().await {
            let chunk = chunk.map_err(|e| {
                error!("Error reading multipart chunk: {}", e);
                error::ErrorInternalServerError("Error reading file data")
            })?;
            
            // Check file size limit while reading
            data.extend_from_slice(&chunk);
            if !validate_file_size(data.len() as u64) {
                return Err(error::ErrorBadRequest("File too large"));
            }
        }
        
        // Save the file to disk temporarily
        save_file_to_disk(&data, &temp_path).map_err(|e| {
            error!("Error saving file: {}", e);
            error::ErrorInternalServerError("Error saving file")
        })?;
        
        // Create temporary file info
        let temp_file_info = FileInfo::new(
            filename.clone(),
            data.len() as u64,
            content_type,
            temp_path.clone(),
        );
        
        // Generate a path for the encrypted file
        let encrypted_path = get_encrypted_path(&format!("{}.encrypted", filename));
        
        // Encrypt the file
        match encrypt_file_util(
            &temp_path,
            &encrypted_path,
            &encrypt_req.passphrase,
        ) {
            Ok(_) => {
                // Get the size of the encrypted file
                let encrypted_size = fs::metadata(&encrypted_path)
                    .map(|m| m.len())
                    .unwrap_or(0);
                
                // Create file info for the encrypted file
                let encrypted_file_info = FileInfo::new_encrypted(
                    &temp_file_info,
                    encrypted_path,
                    encrypted_size,
                );
                
                // Store file info
                file_store.add_file(encrypted_file_info.clone());
                
                info!("File uploaded and encrypted: {}", encrypted_file_info.id);
                
                // Delete the temporary file
                if let Err(e) = fs::remove_file(&temp_path) {
                    warn!("Failed to delete temporary file: {}", e);
                    // Continue even if deletion fails
                }
                
                // Return success response
                return Ok(HttpResponse::Ok().json(FileResponse {
                    success: true,
                    message: "File uploaded and encrypted successfully".to_string(),
                    file: Some(encrypted_file_info),
                }));
            },
            Err(e) => {
                // Delete the temporary file
                if let Err(delete_err) = fs::remove_file(&temp_path) {
                    warn!("Failed to delete temporary file: {}", delete_err);
                }
                
                error!("Error encrypting file: {:?}", e);
                return Err(error::ErrorInternalServerError("Error encrypting file"));
            }
        }
    }
    
    // If we get here, no file was uploaded
    Err(error::ErrorBadRequest("No file uploaded"))
}

/// Download a file
pub async fn download_file(
    path: web::Path<String>,
    file_store: web::Data<FileStore>,
) -> Result<HttpResponse, Error> {
    let file_id = path.into_inner();
    
    // Get the file info
    let file_info = match file_store.get_file(&file_id) {
        Some(file) => file,
        None => return Err(error::ErrorNotFound("File not found")),
    };
    
    // Read the file
    let mut file = match fs::File::open(&file_info.path) {
        Ok(file) => file,
        Err(e) => {
            error!("Error opening file: {}", e);
            return Err(error::ErrorInternalServerError("Error opening file"));
        }
    };
    
    // Read file content into a buffer
    let mut buffer = Vec::new();
    if let Err(e) = file.read_to_end(&mut buffer) {
        error!("Error reading file: {}", e);
        return Err(error::ErrorInternalServerError("Error reading file"));
    }
    
    // Determine content type
    let content_type = file_info.content_type.clone()
        .unwrap_or_else(|| "application/octet-stream".to_string());
    
    // Build response with file content
    Ok(HttpResponse::Ok()
        .content_type(content_type)
        .append_header((
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", file_info.filename),
        ))
        .body(buffer))
}
