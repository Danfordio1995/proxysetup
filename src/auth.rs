use warp::{Filter, Rejection, Reply};
use crate::users::{UserManager, LoginRequest, CreateUserRequest, UserRole, Claims};
use serde_json::json;
use std::convert::Infallible;

pub async fn auth_middleware(token: String) -> Result<Claims, Rejection> {
    if let Some(claims) = UserManager::verify_token(&token).await {
        Ok(claims)
    } else {
        Err(warp::reject::custom(AuthError::InvalidToken))
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
    warp::header::<String>("Authorization")
        .map(|token: String| token.replace("Bearer ", ""))
        .and_then(auth_middleware)
}

pub async fn handle_login(login: LoginRequest) -> Result<impl Reply, Rejection> {
    if let Some(token) = UserManager::authenticate(&login.username, &login.password).await {
        Ok(warp::reply::json(&json!({
            "token": token,
            "message": "Login successful"
        })))
    } else {
        Err(warp::reject::custom(AuthError::InvalidCredentials))
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
    if let Some(users) = UserManager::get_users(&claims.role).await {
        Ok(warp::reply::json(&users))
    } else {
        Err(warp::reject::custom(AuthError::InsufficientPermissions))
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
pub async fn handle_rejection(err: Rejection) -> Result<impl Reply, Infallible> {
    let (code, message) = if err.is_not_found() {
        (404, "Not Found")
    } else if let Some(AuthError::InvalidToken) = err.find() {
        (401, "Invalid token")
    } else if let Some(AuthError::InvalidCredentials) = err.find() {
        (401, "Invalid credentials")
    } else if let Some(AuthError::InsufficientPermissions) = err.find() {
        (403, "Insufficient permissions")
    } else {
        (500, "Internal Server Error")
    };

    Ok(warp::reply::with_status(
        warp::reply::json(&json!({
            "error": message
        })),
        warp::http::StatusCode::from_u16(code).unwrap(),
    ))
} 