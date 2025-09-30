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
type VulnerableCache = Arc<DashMap<u32, User>>;

// Secure: A Moka cache with a defined maximum capacity.
// The cache stores Arc<User> to avoid cloning the large User struct on every cache hit.
type SecureCache = Cache<u32, User>;

// --- Simulated Helper Functions ---

/// Simulates fetching a user from a database.
/// This is an expensive operation we want to cache.
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
fn is_admin() -> bool {
    false
}

// --- Endpoint Handlers ---

/// VULNERABLE endpoint handler.
async fn vulnerable_user(
    user_id: web::Path<u32>,
    cache: web::Data<VulnerableCache>,
) -> impl Responder {
    let id = user_id.into_inner();

    if let Some(user_entry) = cache.get(&id) {
        let user = user_entry.value().clone();
        println!("VULNERABLE CACHE HIT: Found user {} in cache.", id);
        if !is_admin() {
            return HttpResponse::Forbidden().json("Permission denied");
        }
        return HttpResponse::Ok().json(user);
    }

    if let Some(user) = fetch_user_from_database(id).await {
        println!("VULNERABLE: Storing user {} in unbounded cache.", id);
        cache.insert(id, user.clone());
        if !is_admin() {
            return HttpResponse::Forbidden().json("Permission denied");
        }
        HttpResponse::Ok().json(user)
    } else {
        HttpResponse::NotFound().json("User not found")
    }
}

/// SECURE endpoint handler.
async fn secure_user(user_id: web::Path<u32>, cache: web::Data<SecureCache>) -> impl Responder {
    let id = user_id.into_inner();

    if !is_admin() {
        return HttpResponse::Forbidden().json("Permission denied");
    }

    // We convert our database function's Option<User> to a Result<User, &str>.
    let result = cache
        .try_get_with(id, async {
            fetch_user_from_database(id).await.ok_or("User not in DB") // Convert Option to Result for try_get_with
        })
        .await;

    match result {
        // On success, `try_get_with` returns Ok(Arc<User>).
        // We serialize the underlying User struct.
        Ok(user) => HttpResponse::Ok().json(user),
        // On failure, it returns the error from our future.
        Err(_) => HttpResponse::NotFound().json("User not found"),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Starting server at http://127.0.0.1:8080");

    // Initialize the unbounded cache for the vulnerable endpoint
    // Your explicit type annotation is good practice!
    let vulnerable_cache = web::Data::new(Arc::new(DashMap::<u32, User>::new()));

    // Initialize the Moka cache for the secure endpoint
    let secure_cache = web::Data::new(Cache::<u32, User>::builder().max_capacity(100).build());

    HttpServer::new(move || {
        App::new()
            .app_data(vulnerable_cache.clone())
            .app_data(secure_cache.clone())
            .route("/vulnerable/user/{id}", web::get().to(vulnerable_user))
            .route("/secure/user/{id}", web::get().to(secure_user))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
