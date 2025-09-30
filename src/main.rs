use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use dashmap::DashMap;
use moka::future::Cache;
use serde::Serialize;
use std::sync::Arc;
use tokio::time::{sleep, Duration};

// A simple User struct that we'll be serving.
// It includes a large vector to simulate storing memory-intensive data like a profile picture.
#[derive(Debug, Serialize, Clone)]
struct User {
    id: u32,
    name: String,
    email: String,
    profile_picture_data: Vec<u8>, // Simulates a large data blob
}

// --- Shared State for Caching ---

// Vulnerable: A DashMap that grows without bounds.
// DashMap is a thread-safe HashMap, suitable for sharing across Actix workers.
type VulnerableCache = Arc<DashMap<u32, User>>;

// Secure: A Moka cache with a defined maximum capacity.
// Once it reaches 100 items, it will start evicting older entries.
type SecureCache = Cache<u32, User>;

// --- Simulated Helper Functions ---

/// Simulates fetching a user from a database.
/// This is an expensive operation we want to cache.
/// We add a small delay to represent network/database latency.
async fn fetch_user_from_database(user_id: u32) -> Option<User> {
    println!("CACHE MISS: Fetching user {} from the database...", user_id);
    sleep(Duration::from_millis(50)).await;
    Some(User {
        id: user_id,
        name: format!("User {}", user_id),
        email: format!("user{}@example.com", user_id),
        // Allocate 100 KB for each user to make memory growth noticeable.
        profile_picture_data: vec![0; 1024 * 100],
    })
}

/// Simulates checking if the current logged-in user has admin privileges.
/// In this demo, we'll hardcode it to `false` to simulate an attacker
/// who does not have permission to view user profiles.
fn is_admin() -> bool {
    false
}

// --- Endpoint Handlers ---

/// VULNERABLE endpoint handler.
/// This handler fetches user data *before* checking permissions and stores it
/// in a cache that can grow indefinitely.
async fn vulnerable_user(
    user_id: web::Path<u32>,
    cache: web::Data<VulnerableCache>,
) -> impl Responder {
    let id = user_id.into_inner();

    // Check if the user is in the cache.
    if let Some(user_entry) = cache.get(&id) {
        let user = user_entry.value().clone();
        println!("VULNERABLE CACHE HIT: Found user {} in cache.", id);
        // NOTE: The permission check is still done *after* retrieving from cache,
        // but the main flaw is adding to the cache without bounds.
        if !is_admin() {
            return HttpResponse::Forbidden().json("Permission denied");
        }
        return HttpResponse::Ok().json(user);
    }

    // --- The Leak Logic ---
    // 1. Fetch from the "database" even if the requester is unauthorized.
    // 2. Store the result in the unbounded cache.
    if let Some(user) = fetch_user_from_database(id).await {
        println!("VULNERABLE: Storing user {} in unbounded cache.", id);
        cache.insert(id, user.clone());

        // 2. Check permissions *after* the expensive operation and caching.
        // An attacker without permissions can still force the server to fetch and cache data,
        // consuming memory with every unique ID they request.
        if !is_admin() {
            return HttpResponse::Forbidden().json("Permission denied");
        }

        HttpResponse::Ok().json(user)
    } else {
        HttpResponse::NotFound().json("User not found")
    }
}

/// SECURE endpoint handler.
/// This handler checks permissions *first* and uses a bounded cache
/// to prevent memory exhaustion.
async fn secure_user(user_id: web::Path<u32>, cache: web::Data<SecureCache>) -> impl Responder {
    let id = user_id.into_inner();

    // --- The Fix ---
    // 1. Perform the cheap permission check *before* any expensive operations.
    if !is_admin() {
        // We deny access immediately, preventing any database/cache interaction.
        return HttpResponse::Forbidden().json("Permission denied");
    }

    // 2. Use a bounded cache with a "get_with" operation.
    // The `get_with` function will either return the cached value or execute the
    // provided async block to fetch and insert the value if it's missing.
    // This is both efficient and memory-safe due to the cache's size limit.
    match cache.get_with(id, fetch_user_from_database(id)).await {
        Some(user) => HttpResponse::Ok().json(user),
        None => HttpResponse::NotFound().json("User not found"),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Starting server at http://127.0.0.1:8080");

    // Initialize the unbounded cache for the vulnerable endpoint
    let vulnerable_cache = web::Data::new(Arc::new(DashMap::new()));

    // Initialize the Moka cache for the secure endpoint with a max capacity of 100 items.
    let secure_cache = web::Data::new(Cache::builder().max_capacity(100).build());

    HttpServer::new(move || {
        App::new()
            .app_data(vulnerable_cache.clone()) // Register vulnerable cache
            .app_data(secure_cache.clone()) // Register secure cache
            .route("/vulnerable/user/{id}", web::get().to(vulnerable_user))
            .route("/secure/user/{id}", web::get().to(secure_user))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
