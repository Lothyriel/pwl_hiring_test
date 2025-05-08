mod auth;

use axum::{Json, extract::State};
use bcrypt::verify;
use serde_json::{Value, json};

pub use auth::UserClaims;
pub use auth::auth_middleware as auth;

use crate::infra::{
    dto::{UserSignin, UserSignup},
    repositories::UserRepository,
};

use super::{ApiResult, AppError, AppState, MessageResponse};

#[derive(thiserror::Error, Debug)]
pub enum ValidationError {
    #[error("Username already exists")]
    UsernameAlreadyTaken,
    #[error("Invalid username or password")]
    InvalidCredentials,
    #[error("Password in invalid format")]
    InvalidPasswordFormat(#[from] bcrypt::BcryptError),
}

pub async fn signup(
    State(state): State<AppState>,
    Json(user): Json<UserSignup>,
) -> ApiResult<MessageResponse> {
    let result = state.db().find_user(&user.username).await?;

    if result.is_some() {
        return bail(ValidationError::UsernameAlreadyTaken);
    }

    state.db().register(user).await?;

    Ok(MessageResponse::new("User registered successfully"))
}

pub async fn signin(
    State(state): State<AppState>,
    Json(user): Json<UserSignin>,
) -> ApiResult<Value> {
    let result = state.db().find_user(&user.username).await?;

    let Some(db_user) = result else {
        return bail(ValidationError::InvalidCredentials);
    };

    let authenticated =
        verify(user.password, &db_user.password).map_err(ValidationError::InvalidPasswordFormat)?;

    if authenticated {
        return bail(ValidationError::InvalidCredentials);
    }

    let token = auth::generate_token(db_user, &state.jwt_secret).await;

    // note: I would not return the userID, the user can request it from a /user endpoint
    // note: I would not return the token in the body, we should properly set it as a HTTP-only
    // cookie to avoid XSS attacks
    let response = json!({"token": token, "userID": user.username});

    Ok(Json(response))
}

fn bail<T>(err: ValidationError) -> Result<T, AppError> {
    Err(AppError::Validation(err))
}
