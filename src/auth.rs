use warp::{Filter, Rejection, Reply};
use crate::users::{UserManager, LoginRequest, CreateUserRequest, Claims};
use serde_json::json;
use std::convert::Infallible;
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};

pub async fn auth_middleware(token: String) -> Result<Claims, Rejection> {
    match UserManager::verify_token(&token).await {
        Ok(claims) => Ok(claims),
        Err(_) => Err(warp::reject::custom(AuthError::InvalidToken)),
    }
}

#[derive(Debug)]
pub enum AuthError {
    InvalidToken,
    InvalidCredentials,
    InsufficientPermissions,
}

impl warp::reject::Reject for AuthError {}

pub fn with_auth() -> impl Filter<Extract = (Claims,), Error = Rejection> + Clone {
    warp::header::optional("authorization")
        .and_then(|auth_header: Option<String>| async move {
            match auth_header {
                Some(header) if header.starts_with("Bearer ") => {
                    let token = header.trim_start_matches("Bearer ").trim();
                    match UserManager::verify_token(token).await {
                        Ok(claims) => Ok(claims),
                        Err(_) => Err(warp::reject::custom(AuthError::InvalidToken))
                    }
                }
                _ => Err(warp::reject::custom(AuthError::InvalidCredentials))
            }
        })
}

pub async fn handle_login(login: LoginRequest) -> Result<impl Reply, Rejection> {
    match UserManager::authenticate(&login.username, &login.password).await {
        Ok(token) => Ok(warp::reply::json(&json!({
            "token": token,
            "message": "Login successful"
        }))),
        Err(e) => {
            log::warn!("Login failed for user {}: {}", login.username, e);
            Err(warp::reject::custom(AuthError::InvalidCredentials))
        }
    }
}

pub async fn handle_create_user(
    claims: Claims,
    create_request: CreateUserRequest,
) -> Result<impl Reply, Rejection> {
    match UserManager::create_user(create_request, &claims.role).await {
        Ok(()) => Ok(warp::reply::json(&json!({
            "message": "User created successfully"
        }))),
        Err(e) => Ok(warp::reply::json(&json!({
            "error": e
        })))
    }
}

pub async fn handle_get_users(claims: Claims) -> Result<impl Reply, Rejection> {
    match UserManager::get_users(&claims.role).await {
        Some(users) => Ok(warp::reply::json(&users)),
        None => Err(warp::reject::custom(AuthError::InsufficientPermissions))
    }
}

pub async fn handle_delete_user(
    claims: Claims,
    username: String,
) -> Result<impl Reply, Rejection> {
    match UserManager::delete_user(&username, &claims.role).await {
        Ok(()) => Ok(warp::reply::json(&json!({
            "message": "User deleted successfully"
        }))),
        Err(e) => Ok(warp::reply::json(&json!({
            "error": e
        })))
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
                message = "Invalid token";
            }
            AuthError::InvalidCredentials => {
                code = warp::http::StatusCode::UNAUTHORIZED;
                message = "Invalid credentials";
            }
            AuthError::InsufficientPermissions => {
                code = warp::http::StatusCode::FORBIDDEN;
                message = "Insufficient permissions";
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