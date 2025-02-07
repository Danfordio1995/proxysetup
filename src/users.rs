use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2, Params
};
use rand::Rng;
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use chrono::{Utc, Duration};
use std::fs;
use std::error::Error as StdError;
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

// Rate limiting structures
#[derive(Debug, Clone)]
struct LoginAttempt {
    count: u32,
    last_attempt: u64,
}

const JWT_SECRET: &[u8] = b"your-secret-key"; // In production, use environment variables
const SALT_LENGTH: usize = 32;

lazy_static::lazy_static! {
    static ref USERS: Arc<RwLock<HashMap<String, User>>> = Arc::new(RwLock::new(HashMap::new()));
    static ref LOGIN_ATTEMPTS: Arc<RwLock<HashMap<String, LoginAttempt>>> = Arc::new(RwLock::new(HashMap::new()));
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum UserRole {
    Admin,
    ViewOnly,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub role: UserRole,
    pub exp: usize,
    pub iat: usize,
}

#[derive(Debug, Serialize, Deserialize)]
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

pub struct UserManager;

impl UserManager {
    pub async fn init() -> Result<(), Box<dyn StdError>> {
        dotenv::dotenv().ok();
        
        // Create default admin if no users exist
        let mut users = USERS.write().await;
        if users.is_empty() {
            let admin_username = env::var("ADMIN_USERNAME").unwrap_or_else(|_| "admin".to_string());
            let admin_password = env::var("ADMIN_PASSWORD").unwrap_or_else(|_| "admin123".to_string());
            
            let default_admin = User {
                username: admin_username.clone(),
                password_hash: Self::hash_password(&admin_password).map_err(|e| e.to_string())?,
                role: UserRole::Admin,
                created_at: Utc::now().timestamp(),
                last_login: None,
            };
            users.insert(admin_username, default_admin);
            Self::save_users(&users)?;
            log::info!("Created default admin user");
        }
        Ok(())
    }

    fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            Params::new(65536, 3, 4, None).unwrap()
        );
        Ok(argon2.hash_password(password.as_bytes(), &salt)?.to_string())
    }

    fn verify_password(hash: &str, password: &str) -> Result<bool, argon2::password_hash::Error> {
        let parsed_hash = PasswordHash::new(hash)?;
        let argon2 = Argon2::default();
        match argon2.verify_password(password.as_bytes(), &parsed_hash) {
            Ok(()) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false),
            Err(e) => Err(e),
        }
    }

    async fn check_rate_limit(username: &str) -> Result<(), String> {
        let max_attempts: u32 = env::var("MAX_LOGIN_ATTEMPTS")
            .unwrap_or_else(|_| "5".to_string())
            .parse()
            .unwrap_or(5);
        
        let lockout_duration: u64 = env::var("LOCKOUT_DURATION_MINUTES")
            .unwrap_or_else(|_| "5".to_string())
            .parse()
            .unwrap_or(5) * 60; // Convert to seconds
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let mut attempts = LOGIN_ATTEMPTS.write().await;
        let attempt = attempts.entry(username.to_string()).or_insert(LoginAttempt {
            count: 0,
            last_attempt: now,
        });

        // Reset attempts if lockout duration has passed
        if now - attempt.last_attempt > lockout_duration {
            attempt.count = 0;
        }

        if attempt.count >= max_attempts {
            let time_left = lockout_duration - (now - attempt.last_attempt);
            return Err(format!("Account temporarily locked. Try again in {} minutes", 
                (time_left + 59) / 60)); // Round up to nearest minute
        }

        attempt.count += 1;
        attempt.last_attempt = now;
        Ok(())
    }

    pub async fn authenticate(username: &str, password: &str) -> Result<String, String> {
        // Check rate limiting first
        Self::check_rate_limit(username).await?;

        let users = USERS.read().await;
        if let Some(user) = users.get(username) {
            match Self::verify_password(&user.password_hash, password) {
                Ok(true) => {
                    // Reset login attempts on successful login
                    let mut attempts = LOGIN_ATTEMPTS.write().await;
                    attempts.remove(username);

                    // Generate JWT token
                    let jwt_secret = env::var("JWT_SECRET")
                        .expect("JWT_SECRET must be set in environment");
                    let expiration_hours: i64 = env::var("JWT_EXPIRATION_HOURS")
                        .unwrap_or_else(|_| "24".to_string())
                        .parse()
                        .unwrap_or(24);

                    let now = Utc::now();
                    let exp = now
                        .checked_add_signed(Duration::hours(expiration_hours))
                        .unwrap()
                        .timestamp() as usize;

                    let claims = Claims {
                        sub: username.to_string(),
                        role: user.role.clone(),
                        exp,
                        iat: now.timestamp() as usize,
                    };

                    match encode(
                        &Header::default(),
                        &claims,
                        &EncodingKey::from_secret(jwt_secret.as_bytes()),
                    ) {
                        Ok(token) => {
                            log::info!("✅ User {} authenticated successfully", username);
                            Ok(token)
                        }
                        Err(e) => {
                            log::error!("Failed to generate token: {}", e);
                            Err("Internal server error".to_string())
                        }
                    }
                }
                Ok(false) => {
                    log::warn!("❌ Invalid password for user: {}", username);
                    Err("Invalid username or password".to_string())
                }
                Err(e) => {
                    log::error!("Password verification error for user {}: {}", username, e);
                    Err("Internal server error".to_string())
                }
            }
        } else {
            log::warn!("❌ Authentication attempt for non-existent user: {}", username);
            Err("Invalid username or password".to_string())
        }
    }

    pub async fn verify_token(token: &str) -> Result<Claims, String> {
        let jwt_secret = env::var("JWT_SECRET")
            .expect("JWT_SECRET must be set in environment");

        match decode::<Claims>(
            token,
            &DecodingKey::from_secret(jwt_secret.as_bytes()),
            &Validation::default(),
        ) {
            Ok(token_data) => {
                let claims = token_data.claims;
                
                // Verify token hasn't expired
                let now = Utc::now().timestamp() as usize;
                if claims.exp <= now {
                    return Err("Token has expired".to_string());
                }
                
                log::debug!("✅ Token verified successfully for user: {}", claims.sub);
                Ok(claims)
            }
            Err(e) => {
                log::warn!("❌ Token verification failed: {}", e);
                Err("Invalid token".to_string())
            }
        }
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