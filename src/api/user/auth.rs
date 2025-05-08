use axum::{
    Json,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::IntoResponse,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, errors::Error};
use mongodb::bson::{oid::ObjectId, serde_helpers::serialize_object_id_as_hex_string};
use serde_json::json;

use crate::{api::AppState, infra::dto::ReadHashedUser};

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct UserClaims {
    #[serde(serialize_with = "serialize_object_id_as_hex_string")]
    pub id: ObjectId,
    pub username: String,
}

#[derive(thiserror::Error, Debug)]
pub enum AuthError {
    #[error("Auth token not found on the request")]
    TokenNotPresent,
    #[error("Invalid token: ({0})")]
    JwtValidation(#[from] jsonwebtoken::errors::Error),
}

pub async fn generate_token(user: ReadHashedUser, secret: &str) -> String {
    let data = UserClaims {
        username: user.username,
        id: user.id,
    };

    let now = Utc::now();

    let claims = JwtPayload {
        data,
        iss: ISSUER,
        exp: (now + Duration::hours(1)).timestamp(),
        nbf: now.timestamp(),
    };

    let result = jsonwebtoken::encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    );

    result.expect("Failed to encode JWT")
}

pub async fn auth_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<impl IntoResponse, AuthError> {
    let cookie = req
        .headers()
        .get(axum::http::header::COOKIE)
        .ok_or(AuthError::TokenNotPresent)?;

    let token = cookie.to_str().map_err(|_| AuthError::TokenNotPresent)?;

    let claims = decode_claims(state.jwt_secret(), token).await?;

    req.extensions_mut().insert(claims);

    Ok(next.run(req).await)
}

impl IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        let body = Json(json!({"error": self.to_string() }));

        (StatusCode::UNAUTHORIZED, body).into_response()
    }
}

#[derive(serde::Serialize)]
struct JwtPayload {
    data: UserClaims,
    exp: i64,
    nbf: i64,
    iss: &'static str,
}

const ISSUER: &str = "joao.xavier.api";

async fn decode_claims(secret: &str, token: &str) -> Result<UserClaims, Error> {
    let key = DecodingKey::from_secret(secret.as_bytes());

    let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);

    validation.set_issuer(&[ISSUER]);

    let claims = jsonwebtoken::decode(token, &key, &validation)?.claims;

    Ok(claims)
}
