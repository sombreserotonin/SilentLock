use actix_web::{web, App, HttpServer, Responder, HttpResponse};
use actix_files as fs;
use log::{info, error};
use std::io;

mod encryption;
mod handlers;
mod models;
mod utils;

use crate::utils::FileStore;

use tokio::signal;

#[actix_web::main]
async fn main() -> io::Result<()> {
    // Initialize logger
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    
    info!("Starting secure file transfer server");
    
    // Create data directory if it doesn't exist
    std::fs::create_dir_all("./data/uploads")?;
    std::fs::create_dir_all("./data/encrypted")?;
    
    // Create static directory for web UI
    std::fs::create_dir_all("./static")?;
    
    // Initialize file store
    let file_store = web::Data::new(FileStore::new());
    
    // Create a task to handle Ctrl+C
    let ctrl_c = async {
        signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
        info!("Shutdown signal received");
    };
    
    // Start HTTP server
    let server = HttpServer::new(move || {
        App::new()
            // Register the file store
            .app_data(file_store.clone())
            // Serve static files from the static directory
            .service(fs::Files::new("/static", "./static").show_files_listing())
            // API routes
            .service(
                web::scope("/api")
                    .route("/health", web::get().to(health_check))
                    .service(
                        web::scope("/files")
                            .route("/upload", web::post().to(handlers::files::upload_file))
                            .route("/upload-encrypt", web::post().to(handlers::files::upload_encrypt_file))
                            .route("/encrypt", web::post().to(handlers::files::encrypt_file))
                            .route("/decrypt", web::post().to(handlers::files::decrypt_file))
                            .route("/list", web::get().to(handlers::files::list_files))
                            .route("/download/{file_id}", web::get().to(handlers::files::download_file))
                    )
            )
            // Serve index.html for all other routes
            .route("/", web::get().to(index))
            .route("/{filename:.*}", web::get().to(index))
    })
    .bind("127.0.0.1:8080")?
    .run();
    
    // Get the server handle for graceful shutdown
    let server_handle = server.handle();
    
    // Create a task for the server
    let server_task = tokio::spawn(server);
    
    // Wait for shutdown signal
    ctrl_c.await;
    
    // Clean up on shutdown
    info!("Cleaning up files and data...");
    
    // Stop the server gracefully
    server_handle.stop(true).await;
    
    // Clean up data directories
    if let Err(e) = std::fs::remove_dir_all("./data/uploads") {
        error!("Error cleaning up uploads directory: {}", e);
    }
    if let Err(e) = std::fs::remove_dir_all("./data/encrypted") {
        error!("Error cleaning up encrypted directory: {}", e);
    }
    
    // Recreate empty directories
    std::fs::create_dir_all("./data/uploads")?;
    std::fs::create_dir_all("./data/encrypted")?;
    
    info!("Shutdown complete");
    
    // Wait for server to stop
    match server_task.await {
        Ok(result) => result,
        Err(e) => {
            error!("Server task error: {}", e);
            Err(io::Error::new(io::ErrorKind::Other, "Server task failed"))
        }
    }
}

// Health check endpoint
async fn health_check() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

// Serve the index.html file for the frontend
async fn index() -> impl Responder {
    fs::NamedFile::open_async("./static/index.html").await
}
