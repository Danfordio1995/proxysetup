use warp::{Filter, Rejection, Reply};
use crate::users::{UserManager, LoginRequest, CreateUserRequest, Claims};
use serde_json::json;
use std::convert::Infallible;
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use std::env;

pub async fn auth_middleware(token: String) -> Result<Claims, Rejection> {
    match UserManager::verify_token(&token).await {
        Ok(claims) => {
            log::debug!("✅ Token verified in middleware for user: {}", claims.sub);
            Ok(claims)
        }
        Err(e) => {
            log::warn!("❌ Token verification failed in middleware: {}", e);
            Err(warp::reject::custom(AuthError::InvalidToken))
        }
    }
}

#[derive(Debug)]
pub enum AuthError {
    InvalidToken,
    InvalidCredentials,
    InsufficientPermissions,
    RateLimitExceeded(String),
    InternalError(String),
}

impl warp::reject::Reject for AuthError {}

pub fn with_auth() -> impl Filter<Extract = (Claims,), Error = Rejection> + Clone {
    warp::header::optional("authorization")
        .and_then(|auth_header: Option<String>| async move {
            match auth_header {
                Some(header) if header.starts_with("Bearer ") => {
                    let token = header.trim_start_matches("Bearer ").trim();
                    match UserManager::verify_token(token).await {
                        Ok(claims) => {
                            log::debug!("✅ Token verified in filter for user: {}", claims.sub);
                            Ok(claims)
                        }
                        Err(e) => {
                            log::warn!("❌ Token verification failed in filter: {}", e);
                            Err(warp::reject::custom(AuthError::InvalidToken))
                        }
                    }
                }
                _ => {
                    log::warn!("❌ Missing or invalid Authorization header");
                    Err(warp::reject::custom(AuthError::InvalidCredentials))
                }
            }
        })
}

pub async fn handle_login(login: LoginRequest) -> Result<impl Reply, Rejection> {
    log::info!("👤 Login attempt for user: {}", login.username);
    
    match UserManager::authenticate(&login.username, &login.password).await {
        Ok(token) => {
            log::info!("✅ Login successful for user: {}", login.username);
            Ok(warp::reply::json(&json!({
                "token": token,
                "message": "Login successful"
            })))
        }
        Err(e) => {
            if e.contains("temporarily locked") {
                log::warn!("🔒 Rate limit exceeded for user {}: {}", login.username, e);
                Err(warp::reject::custom(AuthError::RateLimitExceeded(e)))
            } else {
                log::warn!("❌ Login failed for user {}: {}", login.username, e);
                Err(warp::reject::custom(AuthError::InvalidCredentials))
            }
        }
    }
}

pub async fn handle_create_user(
    claims: Claims,
    create_request: CreateUserRequest,
) -> Result<impl Reply, Rejection> {
    log::info!("👥 User creation attempt for: {}", create_request.username);
    
    match UserManager::create_user(create_request, &claims.role).await {
        Ok(()) => {
            log::info!("✅ User created successfully");
            Ok(warp::reply::json(&json!({
                "message": "User created successfully"
            })))
        }
        Err(e) => {
            log::error!("❌ User creation failed: {}", e);
            Ok(warp::reply::json(&json!({
                "error": e
            })))
        }
    }
}

pub async fn handle_get_users(claims: Claims) -> Result<impl Reply, Rejection> {
    log::debug!("👥 Fetching users list");
    
    match UserManager::get_users(&claims.role).await {
        Some(users) => {
            log::debug!("✅ Users list retrieved successfully");
            Ok(warp::reply::json(&users))
        }
        None => {
            log::warn!("❌ Insufficient permissions to list users");
            Err(warp::reject::custom(AuthError::InsufficientPermissions))
        }
    }
}

pub async fn handle_delete_user(
    claims: Claims,
    username: String,
) -> Result<impl Reply, Rejection> {
    log::info!("🗑️ User deletion attempt for: {}", username);
    
    match UserManager::delete_user(&username, &claims.role).await {
        Ok(()) => {
            log::info!("✅ User {} deleted successfully", username);
            Ok(warp::reply::json(&json!({
                "message": "User deleted successfully"
            })))
        }
        Err(e) => {
            log::error!("❌ User deletion failed: {}", e);
            Ok(warp::reply::json(&json!({
                "error": e
            })))
        }
    }
}

// Error handling
pub async fn handle_rejection(err: Rejection) -> Result<impl warp::Reply, Infallible> {
    let code;
    let message;

    if err.is_not_found() {
        code = warp::http::StatusCode::NOT_FOUND;
        message = "NOT_FOUND";
    } else if let Some(e) = err.find::<AuthError>() {
        match e {
            AuthError::InvalidToken => {
                code = warp::http::StatusCode::UNAUTHORIZED;
                message = "Invalid or expired token";
            }
            AuthError::InvalidCredentials => {
                code = warp::http::StatusCode::UNAUTHORIZED;
                message = "Invalid username or password";
            }
            AuthError::InsufficientPermissions => {
                code = warp::http::StatusCode::FORBIDDEN;
                message = "Insufficient permissions";
            }
            AuthError::RateLimitExceeded(msg) => {
                code = warp::http::StatusCode::TOO_MANY_REQUESTS;
                message = msg;
            }
            AuthError::InternalError(msg) => {
                code = warp::http::StatusCode::INTERNAL_SERVER_ERROR;
                message = msg;
            }
        }
    } else if let Some(_) = err.find::<warp::reject::MethodNotAllowed>() {
        code = warp::http::StatusCode::METHOD_NOT_ALLOWED;
        message = "Method not allowed";
    } else {
        code = warp::http::StatusCode::INTERNAL_SERVER_ERROR;
        message = "Internal server error";
    }

    let json = warp::reply::json(&serde_json::json!({
        "code": code.as_u16(),
        "message": message,
    }));

    Ok(warp::reply::with_status(json, code))
}

fn decode_token(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let key = DecodingKey::from_secret(b"your-secret-key"); // Replace with your actual secret key
    let validation = Validation::new(Algorithm::HS256);
    let token_data = decode::<Claims>(token, &key, &validation)?;
    Ok(token_data.claims)
} 