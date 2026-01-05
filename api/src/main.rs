use dotenvy::dotenv;
use poem::http::{header, Method};
use poem::{get, listener::TcpListener, post, EndpointExt, Route, Server};

use crate::route::app::{
    get_health, get_user, total_unique_users, total_views, total_views_per_page,
};
use crate::route::user::{google_auth, logout_user, update_email, update_password};
use crate::route::website::{
    create_website, get_avg_resp, get_avg_resp_by_region, get_details_daily, get_details_hourly,
    get_details_last_hour, get_uptime_percentage, get_uptime_percentage_by_region,
    get_users_websites, get_website_recent_status,
};
use crate::route::{
    app::{snippet, track},
    user::{create_user, sign_in_user},
};
use poem::middleware::{CookieJarManager, Cors};
use std::sync::Arc;
use store::store::Store;

pub mod auth_middleware;
pub mod request_input;
pub mod request_output;
pub mod route;

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    dotenv().ok();

    let s = Arc::new(Store::new().await);

    let cors = Cors::new()
    .allow_origin_regex(".*")
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION, header::ACCEPT])
        .allow_credentials(true);

    let app = Route::new()
        .at("/api/health", get(get_health))
        .at("/api/website", post(create_website))
        .at("/api/website/last_hour", post(get_details_last_hour))
        .at("/api/website/hourly", post(get_details_hourly))
        .at("/api/website/daily", post(get_details_daily))
        .at("/api/user/signup", post(create_user))
        .at("/api/user/signin", post(sign_in_user))
        .at("/api/auth/google", post(google_auth))
        .at("/api/snippet", get(snippet))
        .at("/api/track", post(track))
        .at("/api/get_status", post(get_website_recent_status))
        .at("/api/get_total_views_per_page", post(total_views_per_page))
        .at("/api/get_total_unique_users", post(total_unique_users))
        .at("/api/get_total_views", post(total_views))
        .at("/api/get_user", get(get_user))
        .at("/api/user/logout", post(logout_user))
        .at("/api/user/get_all_websites", get(get_users_websites))
        .at("/api/get_avg_resp", post(get_avg_resp))
        .at("/api/get_avg_resp_region", post(get_avg_resp_by_region))
        .at("/api/get_uptime_percentage", post(get_uptime_percentage))
        .at(
            "/api/get_uptime_percentage_region",
            post(get_uptime_percentage_by_region),
        )
        .at("/api/update_email", post(update_email))
        .at("/api/update_password", post(update_password))
        .data(s)
        .with(cors)
        .with(CookieJarManager::new());

    Server::new(TcpListener::bind("0.0.0.0:3001"))
        .run(app)
        .await
}
