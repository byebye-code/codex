//! 88code API client for fetching usage information.
//!
//! This module provides async functions to query the 88code usage API
//! and returns structured data for display in the status line.
//!
//! Supported API endpoints:
//! - POST /api/usage - Get subscription quota usage
//! - POST /api/subscription - Get all subscriptions with reset info
//! - GET /admin-api/login/getLoginInfo - Get user info and service tier
//! - GET /admin-api/cc-admin/user/model-usage-timeline - Get daily usage timeline

use chrono::NaiveDate;
use serde::Deserialize;
use std::time::Duration;

/// API endpoint for 88code usage information.
const USAGE_API_URL: &str = "https://www.88code.org/api/usage";
/// API endpoint for subscription list with reset times.
const SUBSCRIPTION_API_URL: &str = "https://www.88code.org/api/subscription";
/// API endpoint for login info (includes service tier).
const LOGIN_INFO_API_URL: &str = "https://www.88code.org/admin-api/login/getLoginInfo";
/// API endpoint for daily usage timeline.
const TIMELINE_API_URL: &str =
    "https://www.88code.org/admin-api/cc-admin/user/model-usage-timeline";

/// Request timeout in seconds.
const TIMEOUT_SECS: u64 = 10;

/// Response wrapper from the 88code API.
#[derive(Debug, Deserialize)]
pub(crate) struct Code88Response {
    pub code: i32,
    pub ok: bool,
    pub data: Option<Code88Data>,
}

/// Usage data returned by the 88code API (POST /api/usage).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Code88Data {
    /// Total credit limit for the subscription.
    pub credit_limit: Option<f64>,
    /// Current remaining credits.
    pub current_credits: Option<f64>,
    /// List of all subscriptions for this user.
    pub subscription_entity_list: Option<Vec<SubscriptionEntity>>,
}

/// Subscription entity from /api/usage response (simplified).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SubscriptionEntity {
    /// Whether this subscription is active.
    pub is_active: Option<bool>,
    /// Current remaining credits for this subscription.
    pub current_credits: Option<f64>,
    /// Credit limit for this subscription.
    #[allow(dead_code)]
    pub credit_limit: Option<f64>,
    /// Plan type (e.g., "MONTHLY", "PAY_PER_USE").
    #[allow(dead_code)]
    pub plan_type: Option<String>,
    /// Subscription name (e.g., "FREE", "PRO", "PAYGO").
    #[allow(dead_code)]
    pub subscription_name: Option<String>,
}

/// Response for POST /api/subscription.
#[derive(Debug, Deserialize)]
pub(crate) struct SubscriptionListResponse {
    pub code: i32,
    pub ok: bool,
    pub data: Option<Vec<SubscriptionDetail>>,
}

/// Detailed subscription info from /api/subscription.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SubscriptionDetail {
    /// Number of reset times available today.
    pub reset_times: Option<i32>,
    /// Current remaining credits.
    pub current_credits: Option<f64>,
    /// Subscription status: "活跃中", "未开始", "已禁用".
    pub subscription_status: Option<String>,
    /// Whether this subscription is active.
    pub is_active: Option<bool>,
    /// Nested subscription plan details.
    pub subscription_plan: Option<SubscriptionPlan>,
}

/// Subscription plan details.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SubscriptionPlan {
    /// Credit limit for this plan.
    pub credit_limit: Option<f64>,
    /// Plan type: "MONTHLY", "PAY_PER_USE".
    pub plan_type: Option<String>,
}

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

/// Response for GET /admin-api/cc-admin/user/model-usage-timeline.
#[derive(Debug, Deserialize)]
pub(crate) struct TimelineResponse {
    pub code: i32,
    pub ok: bool,
    pub data: Option<Vec<TimelineDayEntry>>,
}

/// Single day entry in the timeline response.
/// Each entry represents one day's aggregated usage data.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TimelineDayEntry {
    /// Date string (e.g., "2025-12-02").
    pub date: Option<String>,
    /// Total cost for this day.
    pub total_cost: Option<f64>,
    /// Total tokens used this day.
    pub total_tokens: Option<i64>,
    /// Total requests made this day.
    pub total_requests: Option<i64>,
}

/// Aggregated 88code usage data for display.
#[derive(Debug, Clone, Default)]
pub(crate) struct Code88AggregatedData {
    /// Service tier (e.g., "LV5", "LV3", "LV1").
    pub service_tier: Option<String>,
    /// Current subscription credit limit (used for loading state detection).
    pub credit_limit: Option<f64>,
    /// Today's total cost (consumed credits).
    pub daily_cost: Option<f64>,
    /// Today's total available quota.
    pub daily_available: Option<f64>,
    /// Today's total tokens used.
    pub daily_tokens: Option<i64>,
    /// Today's total requests.
    pub daily_requests: Option<i64>,
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

/// Create a shared HTTP client for API requests.
fn create_client() -> Result<reqwest::Client, Code88Error> {
    reqwest::Client::builder()
        .user_agent("curl/8.0")
        .build()
        .map_err(|e| Code88Error::Network(e.to_string()))
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

/// Fetches 88code usage information from the API (POST /api/usage).
///
/// # Arguments
/// * `api_key` - The API key for authentication (Bearer token).
///
/// # Returns
/// * `Ok(Code88Data)` - Usage data on success.
/// * `Err(Code88Error)` - Error information on failure.
pub(crate) async fn fetch_88code_usage(api_key: &str) -> Result<Code88Data, Code88Error> {
    let client = create_client()?;

    let response = client
        .post(USAGE_API_URL)
        .header("Authorization", format!("Bearer {api_key}"))
        .header("Accept", "*/*")
        .timeout(Duration::from_secs(TIMEOUT_SECS))
        .send()
        .await
        .map_err(|e| Code88Error::Network(e.to_string()))?;

    check_response_status(response.status())?;

    let body: Code88Response = response
        .json()
        .await
        .map_err(|e| Code88Error::Parse(e.to_string()))?;

    if body.ok && body.code == 0 {
        body.data.ok_or(Code88Error::NoData)
    } else {
        Err(Code88Error::ApiError(body.code))
    }
}

/// Fetches login info to get service tier (GET /admin-api/login/getLoginInfo).
///
/// # Arguments
/// * `login_token` - The login token from 88code-token.json (NOT the 88_ API key).
///
/// # Returns
/// * `Ok(LoginInfoData)` - Login info on success.
/// * `Err(Code88Error)` - Error information on failure.
pub(crate) async fn fetch_login_info(login_token: &str) -> Result<LoginInfoData, Code88Error> {
    let client = create_client()?;

    let response = client
        .get(LOGIN_INFO_API_URL)
        .header("Authorization", format!("Bearer {login_token}"))
        .header("Accept", "*/*")
        .timeout(Duration::from_secs(TIMEOUT_SECS))
        .send()
        .await
        .map_err(|e| Code88Error::Network(e.to_string()))?;

    check_response_status(response.status())?;

    let body: LoginInfoResponse = response
        .json()
        .await
        .map_err(|e| Code88Error::Parse(e.to_string()))?;

    if body.ok && body.code == 0 {
        body.data.ok_or(Code88Error::NoData)
    } else {
        // Check for token expiration error code
        if body.code == TOKEN_EXPIRED_CODE {
            return Err(Code88Error::TokenExpired);
        }
        Err(Code88Error::ApiError(body.code))
    }
}

/// Convert account group code to display tier (e.g., "service_tier5" -> "LV5").
pub(crate) fn parse_service_tier(account_group_code: &str) -> String {
    // Extract number from service_tierN format
    if let Some(num) = account_group_code.strip_prefix("service_tier") {
        format!("LV{num}")
    } else {
        account_group_code.to_uppercase()
    }
}

/// Fetches subscription list with reset times (POST /api/subscription).
///
/// # Arguments
/// * `api_key` - The API key for authentication (Bearer token, 88_ prefix).
///
/// # Returns
/// * `Ok(Vec<SubscriptionDetail>)` - List of subscriptions on success.
/// * `Err(Code88Error)` - Error information on failure.
pub(crate) async fn fetch_subscriptions(
    api_key: &str,
) -> Result<Vec<SubscriptionDetail>, Code88Error> {
    let client = create_client()?;

    let response = client
        .post(SUBSCRIPTION_API_URL)
        .header("Authorization", format!("Bearer {api_key}"))
        .header("Accept", "*/*")
        .timeout(Duration::from_secs(TIMEOUT_SECS))
        .send()
        .await
        .map_err(|e| Code88Error::Network(e.to_string()))?;

    check_response_status(response.status())?;

    let body: SubscriptionListResponse = response
        .json()
        .await
        .map_err(|e| Code88Error::Parse(e.to_string()))?;

    if body.ok && body.code == 0 {
        Ok(body.data.unwrap_or_default())
    } else {
        Err(Code88Error::ApiError(body.code))
    }
}

/// Calculate daily available credits from subscription list.
///
/// Formula:
/// - Only include subscriptions where `subscriptionStatus == "活跃中"` AND `isActive == true`
/// - For PAY_PER_USE (PAYGO): add `currentCredits`
/// - For MONTHLY (PRO/FREE): add `currentCredits + (resetTimes × creditLimit)`
pub(crate) fn calculate_daily_available(subscriptions: &[SubscriptionDetail]) -> f64 {
    subscriptions
        .iter()
        .filter(|sub| {
            // Must be "活跃中" (active status) and isActive == true
            let status_ok = sub
                .subscription_status
                .as_deref()
                .map(|s| s == "活跃中")
                .unwrap_or(false);
            let is_active = sub.is_active.unwrap_or(false);
            status_ok && is_active
        })
        .map(|sub| {
            let current_credits = sub.current_credits.unwrap_or(0.0);
            let plan = sub.subscription_plan.as_ref();
            let plan_type = plan.and_then(|p| p.plan_type.as_deref()).unwrap_or("");

            if plan_type == "PAY_PER_USE" {
                // PAYGO: just currentCredits
                current_credits
            } else {
                // MONTHLY (PRO/FREE): currentCredits + (resetTimes × creditLimit)
                let reset_times = sub.reset_times.unwrap_or(0) as f64;
                let credit_limit = plan.and_then(|p| p.credit_limit).unwrap_or(0.0);
                current_credits + (reset_times * credit_limit)
            }
        })
        .sum()
}

/// Fetches daily usage timeline (GET /admin-api/cc-admin/user/model-usage-timeline).
///
/// # Arguments
/// * `login_token` - The login token from 88code-token.json.
///
/// # Returns
/// * `Ok(Vec<TimelineDayEntry>)` - Timeline entries (one per day) on success.
/// * `Err(Code88Error)` - Error information on failure.
pub(crate) async fn fetch_timeline(
    login_token: &str,
) -> Result<Vec<TimelineDayEntry>, Code88Error> {
    let client = create_client()?;

    let response = client
        .get(TIMELINE_API_URL)
        .header("Authorization", format!("Bearer {login_token}"))
        .header("Accept", "*/*")
        .timeout(Duration::from_secs(TIMEOUT_SECS))
        .send()
        .await
        .map_err(|e| Code88Error::Network(e.to_string()))?;

    check_response_status(response.status())?;

    let body: TimelineResponse = response
        .json()
        .await
        .map_err(|e| Code88Error::Parse(e.to_string()))?;

    if body.ok && body.code == 0 {
        Ok(body.data.unwrap_or_default())
    } else {
        // Check for token expiration error code
        if body.code == TOKEN_EXPIRED_CODE {
            return Err(Code88Error::TokenExpired);
        }
        Err(Code88Error::ApiError(body.code))
    }
}

/// Calculate total available credits from all active subscriptions.
///
/// This sums up `currentCredits` from all subscriptions where `isActive=true`.
/// Falls back to the single subscription's `currentCredits` if no subscription list.
fn calculate_total_available(usage_data: &Code88Data) -> Option<f64> {
    if let Some(subscriptions) = &usage_data.subscription_entity_list
        && !subscriptions.is_empty()
    {
        let total: f64 = subscriptions
            .iter()
            .filter(|sub| sub.is_active.unwrap_or(false))
            .filter_map(|sub| sub.current_credits)
            .sum();
        return Some(total);
    }
    // Fallback to single subscription credits
    usage_data.current_credits
}

/// Get today's usage data from timeline entries.
/// The timeline API returns one entry per day, we need to find today's entry.
/// The last entry in the list is typically today's data.
fn get_today_usage(entries: &[TimelineDayEntry]) -> (f64, i64, i64) {
    let newest = entries
        .iter()
        .filter_map(|entry| {
            let date_str = entry.date.as_deref()?;
            let date = NaiveDate::parse_from_str(date_str, "%Y-%m-%d").ok()?;
            Some((date, entry))
        })
        .max_by_key(|(date, _)| *date)
        .map(|(_, entry)| entry);

    let entry = newest.or_else(|| entries.last());

    if let Some(entry) = entry {
        let cost = entry.total_cost.unwrap_or(0.0);
        let tokens = entry.total_tokens.unwrap_or(0);
        let requests = entry.total_requests.unwrap_or(0);
        (cost, tokens, requests)
    } else {
        (0.0, 0, 0)
    }
}

/// Fetch all 88code data aggregated into a single structure.
///
/// This function fetches data from multiple API endpoints and combines them.
///
/// # Arguments
/// * `login_token` - The login token from 88code-token.json for getLoginInfo API.
/// * `api_key` - The 88_ prefixed API key for usage API.
///
/// # Returns
/// * `Ok(Code88AggregatedData)` - Aggregated usage data on success.
/// * `Err(Code88Error)` - Error information on failure.
pub(crate) async fn fetch_88code_aggregated(
    login_token: &str,
    api_key: &str,
) -> Result<Code88AggregatedData, Code88Error> {
    // Fetch all data concurrently
    // - login_token is used for getLoginInfo (service tier) and timeline API
    // - api_key (88_ prefix) is used for usage API and subscription API
    let (usage_result, login_result, timeline_result, subscription_result) = tokio::join!(
        fetch_88code_usage(api_key),
        fetch_login_info(login_token),
        fetch_timeline(login_token),
        fetch_subscriptions(api_key),
    );

    // Process login info first to check for token expiration
    let service_tier = match &login_result {
        Ok(info) => info
            .account_group_code
            .as_ref()
            .map(|code| parse_service_tier(code)),
        Err(Code88Error::TokenExpired) => {
            // Token expired - propagate this error
            return Err(Code88Error::TokenExpired);
        }
        Err(_) => None, // Other errors - continue with None
    };

    // Process usage data (required)
    let usage_data = usage_result?;

    // Process timeline data for daily usage stats (today's data)
    let (daily_cost, daily_tokens, daily_requests) = match timeline_result {
        Ok(entries) => {
            let (cost, tokens, requests) = get_today_usage(&entries);
            (Some(cost), Some(tokens), Some(requests))
        }
        Err(Code88Error::TokenExpired) => {
            // Token expired - propagate this error
            return Err(Code88Error::TokenExpired);
        }
        Err(_) => {
            // Timeline API failed, use usage API data for consumed credits
            let consumed = usage_data
                .credit_limit
                .zip(usage_data.current_credits)
                .map(|(limit, current)| limit - current)
                .unwrap_or(0.0);
            (Some(consumed), None, None)
        }
    };

    // Calculate daily available from subscription list
    // Formula: sum of (currentCredits + resetTimes × creditLimit) for active MONTHLY subscriptions
    //        + currentCredits for active PAYGO subscriptions
    let daily_available = match subscription_result {
        Ok(subscriptions) => Some(calculate_daily_available(&subscriptions)),
        Err(_) => {
            // Fallback to simple calculation if subscription API fails
            calculate_total_available(&usage_data)
        }
    };

    Ok(Code88AggregatedData {
        service_tier,
        credit_limit: usage_data.credit_limit,
        daily_cost,
        daily_available,
        daily_tokens,
        daily_requests,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_code88_data_deserialize() {
        let json = r#"{
            "code": 0,
            "level": null,
            "msg": "操作成功",
            "ok": true,
            "data": {
                "id": 27995,
                "subscriptionName": "FREE",
                "creditLimit": 20.0000000000,
                "currentCredits": 6.3234955000,
                "totalCost": 117.022309
            }
        }"#;

        let response: Code88Response = serde_json::from_str(json).unwrap();
        assert!(response.ok);
        assert_eq!(response.code, 0);

        let data = response.data.unwrap();
        assert_eq!(data.credit_limit, Some(20.0));
        assert_eq!(data.current_credits, Some(6.3234955000));
    }

    #[test]
    fn test_code88_data_with_subscriptions() {
        let json = r#"{
            "code": 0,
            "ok": true,
            "data": {
                "creditLimit": 20.0,
                "currentCredits": 13.76,
                "subscriptionEntityList": [
                    {"isActive": true, "currentCredits": 13.76, "creditLimit": 20.0, "planType": "MONTHLY", "subscriptionName": "FREE"},
                    {"isActive": true, "currentCredits": 2.95, "creditLimit": 60.0, "planType": "MONTHLY", "subscriptionName": "PRO"},
                    {"isActive": false, "currentCredits": 27.74, "creditLimit": 30.0, "planType": "PAY_PER_USE", "subscriptionName": "PAYGO"}
                ]
            }
        }"#;

        let response: Code88Response = serde_json::from_str(json).unwrap();
        let data = response.data.unwrap();

        // Test calculate_total_available sums only active subscriptions
        let total = calculate_total_available(&data);
        // Should be 13.76 + 2.95 = 16.71 (excluding inactive PAYGO)
        assert!((total.unwrap() - 16.71).abs() < 0.01);
    }

    #[test]
    fn test_calculate_total_available_fallback() {
        let data = Code88Data {
            credit_limit: Some(20.0),
            current_credits: Some(15.0),
            subscription_entity_list: None,
        };
        assert_eq!(calculate_total_available(&data), Some(15.0));
    }

    #[test]
    fn test_calculate_daily_available() {
        // Test data based on actual API response:
        // PRO (41708): 活跃中, isActive=true, MONTHLY, currentCredits=46.14, resetTimes=2, creditLimit=60
        //   -> 46.14 + 2*60 = 166.14
        // PAYGO (32644): 活跃中, isActive=true, PAY_PER_USE, currentCredits=220.83
        //   -> 220.83
        // FREE (25111): 活跃中, isActive=true, MONTHLY, currentCredits=18.41, resetTimes=2, creditLimit=20
        //   -> 18.41 + 2*20 = 58.41
        // PRO (41710): 未开始, isActive=true -> excluded (status not 活跃中)
        // PAYGO (27665): 已禁用, isActive=false -> excluded
        // FREE (21097): 已禁用, isActive=false -> excluded
        let subscriptions = vec![
            SubscriptionDetail {
                reset_times: Some(2),
                current_credits: Some(60.0),
                subscription_status: Some("未开始".to_string()),
                is_active: Some(true),
                subscription_plan: Some(SubscriptionPlan {
                    credit_limit: Some(60.0),
                    plan_type: Some("MONTHLY".to_string()),
                }),
            },
            SubscriptionDetail {
                reset_times: Some(2),
                current_credits: Some(46.14),
                subscription_status: Some("活跃中".to_string()),
                is_active: Some(true),
                subscription_plan: Some(SubscriptionPlan {
                    credit_limit: Some(60.0),
                    plan_type: Some("MONTHLY".to_string()),
                }),
            },
            SubscriptionDetail {
                reset_times: Some(2),
                current_credits: Some(220.83),
                subscription_status: Some("活跃中".to_string()),
                is_active: Some(true),
                subscription_plan: Some(SubscriptionPlan {
                    credit_limit: Some(200.0),
                    plan_type: Some("PAY_PER_USE".to_string()),
                }),
            },
            SubscriptionDetail {
                reset_times: Some(2),
                current_credits: Some(27.74),
                subscription_status: Some("已禁用".to_string()),
                is_active: Some(false),
                subscription_plan: Some(SubscriptionPlan {
                    credit_limit: Some(200.0),
                    plan_type: Some("PAY_PER_USE".to_string()),
                }),
            },
            SubscriptionDetail {
                reset_times: Some(2),
                current_credits: Some(18.41),
                subscription_status: Some("活跃中".to_string()),
                is_active: Some(true),
                subscription_plan: Some(SubscriptionPlan {
                    credit_limit: Some(20.0),
                    plan_type: Some("MONTHLY".to_string()),
                }),
            },
            SubscriptionDetail {
                reset_times: Some(2),
                current_credits: Some(20.0),
                subscription_status: Some("已禁用".to_string()),
                is_active: Some(false),
                subscription_plan: Some(SubscriptionPlan {
                    credit_limit: Some(20.0),
                    plan_type: Some("MONTHLY".to_string()),
                }),
            },
        ];

        let total = calculate_daily_available(&subscriptions);
        // Expected: 166.14 + 220.83 + 58.41 = 445.38
        assert!((total - 445.38).abs() < 0.01);
    }

    #[test]
    fn test_subscription_detail_deserialize() {
        let json = r#"{
            "code": 0,
            "ok": true,
            "data": [
                {
                    "resetTimes": 2,
                    "currentCredits": 46.14,
                    "subscriptionStatus": "活跃中",
                    "isActive": true,
                    "subscriptionPlan": {
                        "creditLimit": 60.0,
                        "planType": "MONTHLY"
                    }
                }
            ]
        }"#;

        let response: SubscriptionListResponse = serde_json::from_str(json).unwrap();
        assert!(response.ok);
        let data = response.data.unwrap();
        assert_eq!(data.len(), 1);
        assert_eq!(data[0].reset_times, Some(2));
        assert_eq!(data[0].current_credits, Some(46.14));
        assert_eq!(data[0].subscription_status.as_deref(), Some("活跃中"));
        assert_eq!(data[0].is_active, Some(true));
        let plan = data[0].subscription_plan.as_ref().unwrap();
        assert_eq!(plan.credit_limit, Some(60.0));
        assert_eq!(plan.plan_type.as_deref(), Some("MONTHLY"));
    }

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

    #[test]
    fn test_timeline_deserialize() {
        let json = r#"{
            "code": 0,
            "ok": true,
            "data": [
                {"date": "2025-12-01", "totalCost": 85.605616, "totalTokens": 76493929, "totalRequests": 1130},
                {"date": "2025-12-02", "totalCost": 46.338579, "totalTokens": 45343995, "totalRequests": 793}
            ]
        }"#;

        let response: TimelineResponse = serde_json::from_str(json).unwrap();
        assert!(response.ok);
        assert_eq!(response.code, 0);

        let data = response.data.unwrap();
        assert_eq!(data.len(), 2);
        assert_eq!(data[0].date.as_deref(), Some("2025-12-01"));
        assert_eq!(data[0].total_cost, Some(85.605616));
        assert_eq!(data[0].total_tokens, Some(76493929));
        assert_eq!(data[0].total_requests, Some(1130));
    }

    #[test]
    fn test_get_today_usage() {
        let entries = vec![
            TimelineDayEntry {
                date: Some("2025-12-01".to_string()),
                total_cost: Some(85.60),
                total_tokens: Some(76493929),
                total_requests: Some(1130),
            },
            TimelineDayEntry {
                date: Some("2025-12-02".to_string()),
                total_cost: Some(46.34),
                total_tokens: Some(45343995),
                total_requests: Some(793),
            },
        ];

        let (cost, tokens, requests) = get_today_usage(&entries);
        assert!((cost - 46.34).abs() < 0.001);
        assert_eq!(tokens, 45343995);
        assert_eq!(requests, 793);
    }

    #[test]
    fn test_get_today_usage_empty() {
        let entries: Vec<TimelineDayEntry> = vec![];
        let (cost, tokens, requests) = get_today_usage(&entries);
        assert!((cost - 0.0).abs() < 0.001);
        assert_eq!(tokens, 0);
        assert_eq!(requests, 0);
    }

    #[test]
    fn test_get_today_usage_descending_order() {
        let entries = vec![
            TimelineDayEntry {
                date: Some("2025-12-02".to_string()),
                total_cost: Some(46.34),
                total_tokens: Some(45343995),
                total_requests: Some(793),
            },
            TimelineDayEntry {
                date: Some("2025-12-01".to_string()),
                total_cost: Some(85.60),
                total_tokens: Some(76493929),
                total_requests: Some(1130),
            },
        ];

        let (cost, tokens, requests) = get_today_usage(&entries);
        assert!((cost - 46.34).abs() < 0.001);
        assert_eq!(tokens, 45343995);
        assert_eq!(requests, 793);
    }

    #[test]
    fn test_get_today_usage_no_parsable_dates_uses_last_entry() {
        let entries = vec![
            TimelineDayEntry {
                date: None,
                total_cost: Some(1.0),
                total_tokens: Some(10),
                total_requests: Some(1),
            },
            TimelineDayEntry {
                date: Some("not-a-date".to_string()),
                total_cost: Some(2.0),
                total_tokens: Some(20),
                total_requests: Some(2),
            },
            TimelineDayEntry {
                date: None,
                total_cost: Some(3.0),
                total_tokens: Some(30),
                total_requests: Some(3),
            },
        ];

        let (cost, tokens, requests) = get_today_usage(&entries);
        assert!((cost - 3.0).abs() < 0.001);
        assert_eq!(tokens, 30);
        assert_eq!(requests, 3);
    }
}
