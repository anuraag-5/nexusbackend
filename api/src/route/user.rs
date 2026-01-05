use std::{env, sync::{Arc}};
use serde_json::json;
use crate::{
    request_input::{CreateUserInput, SignInUserInput, SignInUserInputWithGoogle, UpdateEmailInput, UpdatePasswordInput},
    request_output::{CreateUserOutput, UpdateEmailOutput},
};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use poem::{
    handler,
    http::{header, StatusCode},
    web::{Data, Json},
    Error, Response, Result
};
use serde::{Deserialize, Serialize};
use store::store::Store;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

#[handler]
pub async fn create_user(
    Json(data): Json<CreateUserInput>,
    Data(s): Data<&Arc<Store>>,
) -> Result<Json<CreateUserOutput>, Error> {
    let username = data.username;
    let user_password = data.password;
    let name = data.name;

    let result = s
        .sign_up(username, user_password, name).await
        .map_err(|_| Error::from_status(StatusCode::CONFLICT))?;

    Ok(Json(CreateUserOutput {
        user_id: result,
        success: true,
    }))
}

#[handler]
pub async fn sign_in_user(
    Json(data): Json<SignInUserInput>, // Poem automatically parses JSON here
    Data(s): Data<&Arc<Store>>,
) -> Result<Json<serde_json::Value>> { // Return Json<Value> instead of raw Response
    
    let username = data.username;
    let user_password = data.password;

    // 1. Attempt login
    let user = s.sign_in(username, user_password)
        .await
        .map_err(|_| Error::from_status(StatusCode::UNAUTHORIZED))?; // Return 401 if fails

    // 2. Set Expiration (e.g., 24 hours from now)
    let expiration = Utc::now()
        .checked_add_signed(Duration::hours(24))
        .expect("valid timestamp")
        .timestamp();

    let my_claims = Claims {
        sub: user.id,
        exp: expiration as usize,
    };

    // 3. Encode Token
    // Optimization: Load JWT_SECRET once in 'main.rs' and pass via Data<T> 
    // instead of reading env::var on every request.
    let secret = env::var("JWT_SECRET")
        .map_err(|_| Error::from_string("Server Config Error", StatusCode::INTERNAL_SERVER_ERROR))?;

    let token = encode(
        &Header::default(),
        &my_claims,
        &EncodingKey::from_secret(secret.as_ref()),
    ).map_err(|_| Error::from_status(StatusCode::INTERNAL_SERVER_ERROR))?;

    // 4. Return JSON automatically
    // Poem handles the Content-Type header and serialization for you
    Ok(Json(json!({
        "jwt": token,
        "user_name": user.name // Optional: Send back nice-to-have info
    })))
}

#[handler]
pub async fn google_auth(
    Json(data): Json<SignInUserInputWithGoogle>,
    Data(s): Data<&Arc<Store>>,
) -> Result<Response, Error> {
    let username = data.username;
    let user_password = String::from("GOOGLE_AUTH");
    let user_name = data.user_name;

    let result = s.sign_in_with_google(username.clone()).await;
    let exp = (chrono::Utc::now() + chrono::Duration::days(7)).timestamp() as usize;
    match result {
        Ok(user) => {
            let my_claims = Claims {
                sub: user.id,
                exp: exp.clone(),
            };
            let token = encode(
                &Header::default(),
                &my_claims,
                &EncodingKey::from_secret(env::var("JWT_SECRET").map_err(|_| Error::from_string("Invalid ENV Secret", StatusCode::EXPECTATION_FAILED))?.as_ref()),
            )
            .map_err(|_| Error::from_status(StatusCode::INTERNAL_SERVER_ERROR))?;
            
            let mut resp = Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(format!("{{\"jwt\":\"{}\"}}", token));

            Ok(resp)
        }
        Err(_) => {
            let new_user = s.sign_up(username, user_password, user_name).await;
            match new_user {
                Ok(u) => {
                    let my_claims = Claims {
                        sub: u,
                        exp,
                    };
                    let token = encode(
                        &Header::default(),
                        &my_claims,
                        &EncodingKey::from_secret(env::var("JWT_SECRET").map_err(|_| Error::from_string("Invalid ENV Secret", StatusCode::EXPECTATION_FAILED))?.as_ref()),
                    )
                    .map_err(|_| Error::from_status(StatusCode::INTERNAL_SERVER_ERROR))?;
                    
                    let mut resp = Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(format!("{{\"jwt\":\"{}\"}}", token));
        
                    Ok(resp)
                },
                Err(_) => Err(Error::from_status(StatusCode::INTERNAL_SERVER_ERROR))
            }
        },
    }
}

#[handler]
pub async fn update_email(
    Json(data): Json<UpdateEmailInput>,
    Data(s): Data<&Arc<Store>>,
) -> Json<UpdateEmailOutput> {
    let input_user_id = data.user_id;
    let new_email = data.new_email;

    let result = s.update_email(input_user_id, new_email).await;

    match result {
        Ok(_) => {
            Json(UpdateEmailOutput { success: true })
        }
        Err(_) => Json(UpdateEmailOutput { success: false })
    }
}

#[handler]
pub async fn update_password(
    Json(data): Json<UpdatePasswordInput>,
    Data(s): Data<&Arc<Store>>,
) -> Json<UpdateEmailOutput> {
    let input_user_id = data.user_id;
    let old_password = data.old_password;
    let new_password = data.new_password;

    let result = s.update_password(input_user_id, old_password, new_password).await;

    match result {
        Ok(_) => {
            Json(UpdateEmailOutput { success: true })
        }
        Err(_) => Json(UpdateEmailOutput { success: false })
    }
}

#[handler]
pub async fn logout_user() ->  Response {
    Response::builder()
    .status(StatusCode::OK)
    .header(
        header::SET_COOKIE,
        "jwt=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0",
    )
    .body("Logged out")
}