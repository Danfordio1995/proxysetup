use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use argon2::{self, Config};
use rand::Rng;
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use chrono::{Utc, Duration};
use std::fs;

const JWT_SECRET: &[u8] = b"your-secret-key"; // In production, use environment variables
const SALT_LENGTH: usize = 32;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum UserRole {
    Admin,
    ViewOnly,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    pub username: String,
    pub password_hash: String,
    pub role: UserRole,
    pub created_at: i64,
    pub last_login: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    pub role: UserRole,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub role: UserRole,
    pub exp: i64,
}

lazy_static::lazy_static! {
    static ref USERS: Arc<RwLock<HashMap<String, User>>> = Arc::new(RwLock::new(HashMap::new()));
}

pub struct UserManager;

impl UserManager {
    pub async fn init() -> Result<(), Box<dyn std::error::Error>> {
        // Create default admin if no users exist
        let mut users = USERS.write().await;
        if users.is_empty() {
            let default_admin = User {
                username: "admin".to_string(),
                password_hash: Self::hash_password("admin123")?,
                role: UserRole::Admin,
                created_at: Utc::now().timestamp(),
                last_login: None,
            };
            users.insert("admin".to_string(), default_admin);
            Self::save_users(&users)?;
        }
        Ok(())
    }

    fn hash_password(password: &str) -> Result<String, argon2::Error> {
        let salt: [u8; SALT_LENGTH] = rand::thread_rng().gen();
        let config = Config::default();
        argon2::hash_encoded(password.as_bytes(), &salt, &config)
    }

    fn verify_password(hash: &str, password: &str) -> Result<bool, argon2::Error> {
        argon2::verify_encoded(hash, password.as_bytes())
    }

    pub async fn authenticate(username: &str, password: &str) -> Option<String> {
        let users = USERS.read().await;
        if let Some(user) = users.get(username) {
            if Self::verify_password(&user.password_hash, password).unwrap_or(false) {
                // Generate JWT token
                let expiration = Utc::now()
                    .checked_add_signed(Duration::hours(24))
                    .unwrap()
                    .timestamp();

                let claims = Claims {
                    sub: username.to_string(),
                    role: user.role.clone(),
                    exp: expiration,
                };

                return encode(
                    &Header::default(),
                    &claims,
                    &EncodingKey::from_secret(JWT_SECRET),
                ).ok();
            }
        }
        None
    }

    pub async fn verify_token(token: &str) -> Option<Claims> {
        decode::<Claims>(
            token,
            &DecodingKey::from_secret(JWT_SECRET),
            &Validation::default(),
        ).ok().map(|token_data| token_data.claims)
    }

    pub async fn create_user(request: CreateUserRequest, creator_role: &UserRole) -> Result<(), String> {
        // Only admins can create users
        match creator_role {
            UserRole::Admin => {
                let mut users = USERS.write().await;
                if users.contains_key(&request.username) {
                    return Err("Username already exists".to_string());
                }

                let user = User {
                    username: request.username.clone(),
                    password_hash: Self::hash_password(&request.password)
                        .map_err(|e| format!("Password hashing error: {}", e))?,
                    role: request.role,
                    created_at: Utc::now().timestamp(),
                    last_login: None,
                };

                users.insert(request.username, user);
                Self::save_users(&users)
                    .map_err(|e| format!("Failed to save users: {}", e))?;
                Ok(())
            }
            _ => Err("Insufficient permissions".to_string()),
        }
    }

    fn save_users(users: &HashMap<String, User>) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string_pretty(users)?;
        fs::write("config/users.json", json)?;
        Ok(())
    }

    pub async fn load_users() -> Result<(), Box<dyn std::error::Error>> {
        if let Ok(contents) = fs::read_to_string("config/users.json") {
            let loaded_users: HashMap<String, User> = serde_json::from_str(&contents)?;
            let mut users = USERS.write().await;
            *users = loaded_users;
        }
        Ok(())
    }

    pub async fn get_users(requester_role: &UserRole) -> Option<Vec<String>> {
        match requester_role {
            UserRole::Admin => {
                let users = USERS.read().await;
                Some(users.keys().cloned().collect())
            }
            _ => None,
        }
    }

    pub async fn delete_user(username: &str, requester_role: &UserRole) -> Result<(), String> {
        match requester_role {
            UserRole::Admin => {
                let mut users = USERS.write().await;
                if username == "admin" {
                    return Err("Cannot delete admin user".to_string());
                }
                users.remove(username);
                Self::save_users(&users)
                    .map_err(|e| format!("Failed to save users: {}", e))?;
                Ok(())
            }
            _ => Err("Insufficient permissions".to_string()),
        }
    }
} 