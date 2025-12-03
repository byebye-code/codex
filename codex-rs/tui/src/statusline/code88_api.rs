//! 88code API client for fetching usage information.
//!
//! This module provides async functions to query the 88code dashboard API
//! and returns structured data for display in the status line.
//!
//! Supported API endpoints:
//! - GET /admin-api/login/getLoginInfo - Get user info and service tier
//! - GET /admin-api/cc-admin/user/dashboard - Get today's usage, tokens, and cost

use lazy_static::lazy_static;
use serde::Deserialize;
use std::time::Duration;
use tracing::warn;

/// API endpoint for login info (includes service tier).
const LOGIN_INFO_API_URL: &str = "https://www.88code.org/admin-api/login/getLoginInfo";
/// API endpoint for user dashboard (includes today's usage and cost).
const DASHBOARD_API_URL: &str = "https://www.88code.org/admin-api/cc-admin/user/dashboard";

/// Request timeout in seconds.
const TIMEOUT_SECS: u64 = 10;

/// Response for GET /admin-api/login/getLoginInfo.
#[derive(Debug, Deserialize)]
pub(crate) struct LoginInfoResponse {
    pub code: i32,
    pub ok: bool,
    pub data: Option<LoginInfoData>,
}

/// Login info data containing service tier.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LoginInfoData {
    /// Account group code (e.g., "service_tier5", "service_tier3", "service_tier1").
    pub account_group_code: Option<String>,
}

/// Response for GET /admin-api/cc-admin/user/dashboard.
#[derive(Debug, Deserialize)]
pub(crate) struct DashboardResponse {
    pub code: i32,
    pub ok: bool,
    pub data: Option<DashboardData>,
}

/// Dashboard data containing overview and recent activity.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DashboardData {
    pub recent_activity: Option<RecentActivity>,
}

/// Today's usage activity from dashboard API.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RecentActivity {
    /// Today's total requests.
    pub requests_today: Option<i64>,
    /// Today's total tokens (input + output + cache).
    pub tokens_today: Option<i64>,
    /// Today's input tokens.
    pub input_tokens_today: Option<i64>,
    /// Today's output tokens.
    pub output_tokens_today: Option<i64>,
    /// Today's cache create tokens (cache write).
    pub cache_create_tokens_today: Option<i64>,
    /// Today's cache read tokens.
    pub cache_read_tokens_today: Option<i64>,
    /// Today's total cost in USD.
    pub cost: Option<f64>,
}

/// Aggregated 88code usage data for display.
#[derive(Debug, Clone, Default)]
pub(crate) struct Code88AggregatedData {
    /// Service tier (e.g., "LV5", "LV3", "LV1").
    pub service_tier: Option<String>,
    /// Today's total cost in USD.
    pub daily_cost: Option<f64>,
    /// Today's total tokens used.
    pub daily_tokens: Option<i64>,
    /// Today's total requests.
    pub daily_requests: Option<i64>,
    /// Today's input tokens.
    pub input_tokens: Option<i64>,
    /// Today's output tokens.
    pub output_tokens: Option<i64>,
    /// Today's cache create tokens (cache write).
    pub cache_create_tokens: Option<i64>,
    /// Today's cache read tokens.
    pub cache_read_tokens: Option<i64>,
}

/// API error code indicating token expiration.
const TOKEN_EXPIRED_CODE: i32 = 30007;

/// Error types for 88code API requests.
#[derive(Debug)]
pub(crate) enum Code88Error {
    /// Network or connection error.
    Network(String),
    /// HTTP status code error (includes 401 for token expiration).
    HttpStatus(u16),
    /// JSON parsing error.
    Parse(String),
    /// API returned no data.
    NoData,
    /// API returned an error code.
    ApiError(i32),
    /// Token expired or invalid (needs browser re-login).
    TokenExpired,
}

impl Code88Error {
    /// Check if this error indicates token expiration.
    pub fn is_token_expired(&self) -> bool {
        match self {
            Code88Error::TokenExpired => true,
            Code88Error::HttpStatus(401) => true,
            // API returns code 30007 for expired/invalid token
            Code88Error::ApiError(code) if *code == TOKEN_EXPIRED_CODE => true,
            _ => false,
        }
    }
}

impl std::fmt::Display for Code88Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Code88Error::Network(msg) => write!(f, "Network error: {msg}"),
            Code88Error::HttpStatus(code) => write!(f, "HTTP status error: {code}"),
            Code88Error::Parse(msg) => write!(f, "Parse error: {msg}"),
            Code88Error::NoData => write!(f, "No data returned"),
            Code88Error::ApiError(code) => write!(f, "API error code: {code}"),
            Code88Error::TokenExpired => write!(f, "Token expired"),
        }
    }
}

impl std::error::Error for Code88Error {}

lazy_static! {
    /// Shared HTTP client for all 88code API requests.
    /// Reuses connections via connection pooling for better performance.
    static ref HTTP_CLIENT: reqwest::Client = reqwest::Client::builder()
        .user_agent("curl/8.0")
        .pool_max_idle_per_host(2)
        .build()
        .expect("Failed to create HTTP client");
}

/// Get the shared HTTP client for API requests.
fn get_client() -> &'static reqwest::Client {
    &HTTP_CLIENT
}

/// Handle HTTP response status, detecting token expiration.
fn check_response_status(status: reqwest::StatusCode) -> Result<(), Code88Error> {
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(Code88Error::TokenExpired);
    }
    if !status.is_success() {
        return Err(Code88Error::HttpStatus(status.as_u16()));
    }
    Ok(())
}

/// Fetches login info to get service tier (GET /admin-api/login/getLoginInfo).
pub(crate) async fn fetch_login_info(login_token: &str) -> Result<LoginInfoData, Code88Error> {
    let client = get_client();

    let response = client
        .get(LOGIN_INFO_API_URL)
        .header("Authorization", format!("Bearer {login_token}"))
        .header("Accept", "*/*")
        .timeout(Duration::from_secs(TIMEOUT_SECS))
        .send()
        .await
        .map_err(|e| {
            warn!("88code login info API network error: {}", e);
            Code88Error::Network(e.to_string())
        })?;

    check_response_status(response.status())?;

    let body: LoginInfoResponse = response.json().await.map_err(|e| {
        warn!("88code login info API parse error: {}", e);
        Code88Error::Parse(e.to_string())
    })?;

    if body.ok && body.code == 0 {
        body.data.ok_or_else(|| {
            warn!("88code login info API returned no data");
            Code88Error::NoData
        })
    } else {
        if body.code == TOKEN_EXPIRED_CODE {
            warn!("88code login token expired");
            return Err(Code88Error::TokenExpired);
        }
        warn!("88code login info API error code: {}", body.code);
        Err(Code88Error::ApiError(body.code))
    }
}

/// Fetches dashboard data (GET /admin-api/cc-admin/user/dashboard).
pub(crate) async fn fetch_dashboard(login_token: &str) -> Result<DashboardData, Code88Error> {
    let client = get_client();

    let response = client
        .get(DASHBOARD_API_URL)
        .header("Authorization", format!("Bearer {login_token}"))
        .header("Accept", "*/*")
        .timeout(Duration::from_secs(TIMEOUT_SECS))
        .send()
        .await
        .map_err(|e| {
            warn!("88code dashboard API network error: {}", e);
            Code88Error::Network(e.to_string())
        })?;

    check_response_status(response.status())?;

    let body: DashboardResponse = response.json().await.map_err(|e| {
        warn!("88code dashboard API parse error: {}", e);
        Code88Error::Parse(e.to_string())
    })?;

    if body.ok && body.code == 0 {
        body.data.ok_or_else(|| {
            warn!("88code dashboard API returned no data");
            Code88Error::NoData
        })
    } else {
        if body.code == TOKEN_EXPIRED_CODE {
            warn!("88code dashboard token expired");
            return Err(Code88Error::TokenExpired);
        }
        warn!("88code dashboard API error code: {}", body.code);
        Err(Code88Error::ApiError(body.code))
    }
}

/// Convert account group code to display tier (e.g., "service_tier5" -> "LV5").
pub(crate) fn parse_service_tier(account_group_code: &str) -> String {
    if let Some(num) = account_group_code.strip_prefix("service_tier") {
        format!("LV{num}")
    } else {
        account_group_code.to_uppercase()
    }
}

/// Fetch all 88code data aggregated into a single structure.
///
/// Uses only the dashboard API for today's usage data, plus login info for service tier.
/// Note: `api_key` is kept for API compatibility but currently unused.
#[allow(unused_variables)]
pub(crate) async fn fetch_88code_aggregated(
    login_token: &str,
    api_key: &str,
) -> Result<Code88AggregatedData, Code88Error> {
    // Fetch login info and dashboard data concurrently
    let (login_result, dashboard_result) =
        tokio::join!(fetch_login_info(login_token), fetch_dashboard(login_token),);

    // Process login info for service tier
    let service_tier = match &login_result {
        Ok(info) => info
            .account_group_code
            .as_ref()
            .map(|code| parse_service_tier(code)),
        Err(Code88Error::TokenExpired) => return Err(Code88Error::TokenExpired),
        Err(_) => None,
    };

    // Process dashboard data
    let dashboard = dashboard_result?;
    let activity = dashboard.recent_activity.unwrap_or_default();

    Ok(Code88AggregatedData {
        service_tier,
        daily_cost: activity.cost,
        daily_tokens: activity.tokens_today,
        daily_requests: activity.requests_today,
        input_tokens: activity.input_tokens_today,
        output_tokens: activity.output_tokens_today,
        cache_create_tokens: activity.cache_create_tokens_today,
        cache_read_tokens: activity.cache_read_tokens_today,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_login_info_deserialize() {
        let json = r#"{
            "code": 0,
            "ok": true,
            "data": {
                "accountGroupCode": "service_tier5"
            }
        }"#;

        let response: LoginInfoResponse = serde_json::from_str(json).unwrap();
        assert!(response.ok);
        assert_eq!(response.code, 0);

        let data = response.data.unwrap();
        assert_eq!(data.account_group_code.as_deref(), Some("service_tier5"));
    }

    #[test]
    fn test_dashboard_deserialize() {
        let json = r#"{
            "code": 0,
            "level": null,
            "msg": "操作成功",
            "ok": true,
            "data": {
                "overview": {
                    "totalApiKeys": 4,
                    "activeApiKeys": 4,
                    "totalRequestsUsed": 10910,
                    "totalTokensUsed": 801695968,
                    "cost": 495.306425
                },
                "recentActivity": {
                    "requestsToday": 144,
                    "tokensToday": 11918798,
                    "inputTokensToday": 287093,
                    "outputTokensToday": 68553,
                    "cacheCreateTokensToday": 864125,
                    "cacheReadTokensToday": 10699027,
                    "cost": 12.568282
                },
                "systemHealth": {
                    "redisConnected": true,
                    "uptime": 5229917
                }
            }
        }"#;

        let response: DashboardResponse = serde_json::from_str(json).unwrap();
        assert!(response.ok);
        assert_eq!(response.code, 0);

        let data = response.data.unwrap();
        let activity = data.recent_activity.unwrap();
        assert_eq!(activity.requests_today, Some(144));
        assert_eq!(activity.tokens_today, Some(11918798));
        assert_eq!(activity.input_tokens_today, Some(287093));
        assert_eq!(activity.output_tokens_today, Some(68553));
        assert_eq!(activity.cache_create_tokens_today, Some(864125));
        assert_eq!(activity.cache_read_tokens_today, Some(10699027));
        assert!((activity.cost.unwrap() - 12.568282).abs() < 0.0001);
    }

    #[test]
    fn test_parse_service_tier() {
        assert_eq!(parse_service_tier("service_tier5"), "LV5");
        assert_eq!(parse_service_tier("service_tier3"), "LV3");
        assert_eq!(parse_service_tier("service_tier1"), "LV1");
        assert_eq!(parse_service_tier("unknown"), "UNKNOWN");
    }

    #[test]
    fn test_code88_error_display() {
        assert_eq!(
            Code88Error::Network("timeout".to_string()).to_string(),
            "Network error: timeout"
        );
        assert_eq!(Code88Error::TokenExpired.to_string(), "Token expired");
    }

    #[test]
    fn test_token_expired_detection() {
        assert!(Code88Error::TokenExpired.is_token_expired());
        assert!(Code88Error::HttpStatus(401).is_token_expired());
        assert!(Code88Error::ApiError(30007).is_token_expired());
        assert!(!Code88Error::HttpStatus(500).is_token_expired());
    }
}
