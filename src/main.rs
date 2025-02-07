#[macro_use] extern crate rocket;

use rocket::{State, Request, http::Status, outcome::Outcome, request::{FromRequest}};
use rocket::serde::{json::Json, Deserialize, Serialize};
use sqlx::{PgPool};
use dotenv::dotenv;
use std::env;
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use argon2::{self, Config as ArgonConfig};
use chrono::{Utc, Duration};

/// -------------------------
/// Models and DTOs
/// -------------------------

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub email: String,
    pub password: String, // stored as hashed password
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserDTO {
    pub username: String,
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct RegisterInput {
    pub username: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginInput {
    pub email: String,
    pub password: String,
}

/// JWT Claims structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // user id as string
    pub exp: usize,
}

/// Application state holding the database pool and JWT secret.
pub struct AppState {
    pub db: PgPool,
    pub jwt_secret: String,
}

/// -------------------------
/// Authentication Guard
/// -------------------------

pub struct AuthenticatedUser {
    pub user_id: i32,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthenticatedUser {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        // Expect token in header: "Authorization: Bearer <token>"
        let auth_header = req.headers().get_one("Authorization");
        let token = if let Some(header_value) = auth_header {
            header_value.strip_prefix("Bearer ").unwrap_or("")
        } else {
            ""
        };

        if token.is_empty() {
            return Outcome::Failure((Status::Unauthorized, ()));
        }

        let state = req.guard::<&State<AppState>>().await.unwrap();
        let secret = &state.jwt_secret;
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &Validation::default(),
        );
        match token_data {
            Ok(data) => {
                let user_id = data.claims.sub.parse::<i32>().unwrap_or(0);
                Outcome::Success(AuthenticatedUser { user_id })
            }
            Err(_) => Outcome::Failure((Status::Unauthorized, ())),
        }
    }
}

/// -------------------------
/// Route Handlers
/// -------------------------

// Registration endpoint – creates a new user.
#[post("/register", format = "json", data = "<input>")]
async fn register_user_handler(input: Json<RegisterInput>, state: &State<AppState>) -> Result<Json<UserDTO>, (Status, String)> {
    // Hash the password (using a static salt here for simplicity; use a random salt in production)
    let salt = b"randomsalt";
    let config = ArgonConfig::default();
    let hashed = argon2::hash_encoded(input.password.as_bytes(), salt, &config)
        .map_err(|e| (Status::InternalServerError, e.to_string()))?;

    // Insert user into DB
    let user = sqlx::query_as::<_, User>(
        "INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id, username, email, password"
    )
        .bind(&input.username)
        .bind(&input.email)
        .bind(&hashed)
        .fetch_one(&state.db)
        .await
        .map_err(|e| (Status::InternalServerError, e.to_string()))?;

    Ok(Json(UserDTO { username: user.username, email: user.email }))
}

// Login endpoint – verifies credentials and returns a JWT token.
#[post("/login", format = "json", data = "<input>")]
async fn login_user_handler(input: Json<LoginInput>, state: &State<AppState>) -> Result<Json<String>, (Status, String)> {
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = $1")
        .bind(&input.email)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (Status::InternalServerError, e.to_string()))?;

    let user = match user {
        Some(user) => user,
        None => return Err((Status::Unauthorized, "Invalid credentials".into())),
    };

    // Verify password using argon2
    let valid = argon2::verify_encoded(&user.password, input.password.as_bytes())
        .map_err(|e| (Status::InternalServerError, e.to_string()))?;
    if !valid {
        return Err((Status::Unauthorized, "Invalid credentials".into()));
    }

    // Create JWT token (expires in 24 hours)
    let expiration = Utc::now()
        .checked_add_signed(Duration::hours(24))
        .expect("valid timestamp")
        .timestamp() as usize;
    let claims = Claims { sub: user.id.to_string(), exp: expiration };

    let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(state.jwt_secret.as_bytes()))
        .map_err(|e| (Status::InternalServerError, e.to_string()))?;
    Ok(Json(token))
}

// Protected endpoint: list users (only accessible with valid JWT)
#[get("/users")]
async fn list_users(state: &State<AppState>, _user: AuthenticatedUser) -> Result<Json<Vec<UserDTO>>, (Status, String)> {
    let users = sqlx::query_as::<_, User>("SELECT id, username, email, password FROM users")
        .fetch_all(&state.db)
        .await
        .map_err(|e| (Status::InternalServerError, e.to_string()))?;

    let list = users.into_iter().map(|u| UserDTO { username: u.username, email: u.email }).collect();
    Ok(Json(list))
}

// Example file upload endpoint (uploads are saved to the "uploads" folder)
#[post("/upload", data = "<data>")]
async fn upload_file(data: rocket::Data<'_>) -> Result<&'static str, (Status, String)> {
    use tokio::fs::File;
    use tokio::io::AsyncWriteExt;
    let upload_path = "uploads/uploaded_file.bin";
    // Create (or overwrite) the file
    let mut file = File::create(upload_path).await.map_err(|e| (Status::InternalServerError, e.to_string()))?;
    // For simplicity, read all data (in production, stream to file)
    let bytes = data.open(1.megabyte());
    tokio::io::copy(&mut bytes.into_async_read(), &mut file).await
        .map_err(|e| (Status::InternalServerError, e.to_string()))?;
    Ok("File uploaded")
}

// Example endpoint to delete a user (by id)
#[delete("/users/<id>")]
async fn delete_user(id: i32, state: &State<AppState>, _user: AuthenticatedUser) -> Result<&'static str, (Status, String)> {
    let result = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| (Status::InternalServerError, e.to_string()))?;
    if result.rows_affected() == 0 {
        Err((Status::NotFound, "User not found".into()))
    } else {
        Ok("User deleted")
    }
}

// Update user endpoint (updates username and email)
#[put("/users/<id>", format = "json", data = "<input>")]
async fn update_user(id: i32, input: Json<RegisterInput>, state: &State<AppState>, _user: AuthenticatedUser)
                     -> Result<Json<UserDTO>, (Status, String)>
{
    let user = sqlx::query_as::<_, User>(
        "UPDATE users SET username = $1, email = $2 WHERE id = $3 RETURNING id, username, email, password"
    )
        .bind(&input.username)
        .bind(&input.email)
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| (Status::InternalServerError, e.to_string()))?;
    Ok(Json(UserDTO { username: user.username, email: user.email }))
}

/// -------------------------
/// Rocket Server Launch
/// -------------------------

#[launch]
async fn rocket() -> _ {
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");

    let pool = PgPool::connect(&database_url).await.expect("Failed to connect to DB");

    rocket::build()
        .manage(AppState { db: pool, jwt_secret })
        .mount("/", routes![
            register_user_handler,
            login_user_handler,
            list_users,
            upload_file,
            delete_user,
            update_user
        ])
}
