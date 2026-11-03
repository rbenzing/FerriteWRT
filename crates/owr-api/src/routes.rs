//! Route table and request handlers for `/api/v1`.

use std::future::Future;

use axum::body::Bytes;
use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{FromRequest, FromRequestParts, Path, Query, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::from_fn_with_state;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Extension, Json, Router};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tower_http::limit::RequestBodyLimitLayer;
use zeroize::Zeroizing;

use crate::app::{Actor, AppState, ClientIp, MAX_USERNAME_CHARS, SESSION_COOKIE, rate_limit_key};
use crate::dto::{Role, ServiceAction, UserInfo, ValidationErrors};
use crate::error::{ApiError, ApiResult, ok};
use crate::middleware::{Access, guard};
use crate::password;
use crate::session::SessionView;

/// Request body limit for everything except restore.
pub(crate) const BODY_LIMIT: usize = 256 * 1024;
/// Request body limit for `POST /system/restore`.
pub(crate) const RESTORE_BODY_LIMIT: usize = 1024 * 1024;
const DEFAULT_LOG_LIMIT: u32 = 100;
const MAX_LOG_LIMIT: u32 = 500;
const MAX_SERVICE_NAME_CHARS: usize = 64;

/// Build the `/api/v1` router (state not yet attached).
pub(crate) fn api_router(app: &AppState) -> Router<AppState> {
    let public = Router::new()
        .route("/health", get(health))
        .route("/setup/status", get(setup_status))
        .route("/setup", post(setup))
        .route("/auth/login", post(login));

    let standard = Router::new()
        .route("/board", get(board))
        .route("/system/status", get(system_status))
        .route("/config", get(get_config).put(put_config))
        .route("/config/validate", post(validate_config))
        .route("/network/status", get(network_status))
        .route("/wireless/status", get(wireless_status))
        .route("/dhcp/leases", get(dhcp_leases))
        .route("/firewall/preview", get(firewall_preview))
        .route("/logs", get(logs))
        .route("/services", get(services))
        .route("/services/{name}/{action}", post(service_action))
        .route("/system/reboot", post(reboot))
        .route("/users", get(list_users))
        .route("/users/{name}", put(put_user).delete(delete_user))
        .route_layer(from_fn_with_state((app.clone(), Access::Standard), guard))
        .layer(RequestBodyLimitLayer::new(BODY_LIMIT));

    let self_service = Router::new()
        .route("/auth/session", get(session_info))
        .route("/auth/logout", post(logout))
        .route("/auth/password", post(change_password))
        .route_layer(from_fn_with_state(
            (app.clone(), Access::SelfService),
            guard,
        ))
        .layer(RequestBodyLimitLayer::new(BODY_LIMIT));

    let backup = Router::new()
        .route("/system/backup", get(backup_config))
        .route_layer(from_fn_with_state((app.clone(), Access::AdminOnly), guard));

    let restore = Router::new()
        .route("/system/restore", post(restore_config))
        .route_layer(from_fn_with_state((app.clone(), Access::AdminOnly), guard))
        .layer(RequestBodyLimitLayer::new(RESTORE_BODY_LIMIT));

    Router::new()
        .merge(public.layer(RequestBodyLimitLayer::new(BODY_LIMIT)))
        .merge(standard)
        .merge(self_service)
        .merge(backup)
        .merge(restore)
}

// ---------------------------------------------------------------------------
// Extractors that fail with the JSON error envelope

/// `Json<T>` whose rejection is an [`ApiError`].
struct ApiJson<T>(T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for ApiJson<T> {
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, ApiError> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(v)) => Ok(Self(v)),
            Err(rej) => Err(json_rejection(&rej)),
        }
    }
}

fn json_rejection(rej: &JsonRejection) -> ApiError {
    // Generic messages: serde errors can echo submitted values.
    match rej.status() {
        StatusCode::UNPROCESSABLE_ENTITY => ApiError::validation(&ValidationErrors::single(
            "",
            "request body does not match the expected shape",
        )),
        StatusCode::UNSUPPORTED_MEDIA_TYPE => {
            ApiError::from_status(StatusCode::UNSUPPORTED_MEDIA_TYPE)
        }
        StatusCode::PAYLOAD_TOO_LARGE => ApiError::from_status(StatusCode::PAYLOAD_TOO_LARGE),
        _ => ApiError::bad_request("malformed JSON body"),
    }
}

/// `Query<T>` whose rejection is an [`ApiError`].
struct ApiQuery<T>(T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequestParts<S> for ApiQuery<T> {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, ApiError> {
        Query::<T>::from_request_parts(parts, state)
            .await
            .map(|Query(v)| Self(v))
            .map_err(|_: QueryRejection| ApiError::bad_request("invalid query string"))
    }
}

/// `Path<T>` whose rejection is an [`ApiError`].
struct ApiPath<T>(T);

impl<S: Send + Sync, T: DeserializeOwned + Send> FromRequestParts<S> for ApiPath<T> {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, ApiError> {
        Path::<T>::from_request_parts(parts, state)
            .await
            .map(|Path(v)| Self(v))
            .map_err(|_: PathRejection| ApiError::not_found())
    }
}

// ---------------------------------------------------------------------------
// Public endpoints

async fn health() -> Response {
    ok(Value::Null)
}

async fn setup_status(State(app): State<AppState>) -> ApiResult {
    let needs_setup = app.backend.users().await?.is_empty();
    Ok(ok(json!({ "needs_setup": needs_setup })))
}

#[derive(Deserialize)]
struct Credentials {
    username: String,
    password: String,
}

fn validate_username(name: &str) -> Result<(), ValidationErrors> {
    let valid = !name.is_empty()
        && name.chars().count() <= MAX_USERNAME_CHARS
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if valid {
        Ok(())
    } else {
        Err(ValidationErrors::single(
            "username",
            format!(
                "must be 1-{MAX_USERNAME_CHARS} characters of letters, digits, '.', '_' or '-'"
            ),
        ))
    }
}

fn check_password_policy(username: &str, pw: &str, path: &str) -> Result<(), ValidationErrors> {
    password::check_policy(username, pw).map_err(|msg| ValidationErrors::single(path, msg))
}

/// Argon2id hashing is CPU and memory heavy: keep it off the async workers.
async fn hash_blocking(pw: Zeroizing<String>) -> ApiResult<String> {
    let joined = tokio::task::spawn_blocking(move || password::hash_password(&pw)).await;
    match joined {
        Ok(Ok(hash)) => Ok(hash),
        Ok(Err(e)) => {
            tracing::error!(error = %e, "password hashing failed");
            Err(crate::dto::BackendError::Internal("hashing failed".into()).into())
        }
        Err(e) => {
            tracing::error!(error = %e, "hashing task failed");
            Err(crate::dto::BackendError::Internal("hashing failed".into()).into())
        }
    }
}

fn with_actor(mut response: Response, name: &str) -> Response {
    let actor: String = name.chars().take(MAX_USERNAME_CHARS).collect();
    response.extensions_mut().insert(Actor(actor));
    response
}

/// Run a state-changing operation to completion in its own task. When the request future
/// is dropped (client disconnect, the 30 s timeout) the task is detached, not cancelled,
/// so a backend call is never abandoned half-way; the admin lock and the follow-up
/// session bookkeeping inside `fut` stay consistent with it.
async fn detached(fut: impl Future<Output = ApiResult> + Send + 'static) -> ApiResult {
    match tokio::spawn(fut).await {
        Ok(result) => result,
        Err(e) => {
            tracing::error!(error = %e, "request task failed");
            Err(crate::dto::BackendError::Internal("request task failed".into()).into())
        }
    }
}

async fn setup(State(app): State<AppState>, ApiJson(body): ApiJson<Credentials>) -> ApiResult {
    detached(async move {
        let password = Zeroizing::new(body.password);
        let username = body.username;
        let _guard = app.admin_lock.lock().await;
        if !app.backend.users().await?.is_empty() {
            return Err(ApiError::conflict("setup has already been completed"));
        }
        let mut errors = ValidationErrors::default();
        if let Err(e) = validate_username(&username) {
            errors.errors.extend(e.errors);
        }
        if let Err(e) = check_password_policy(&username, &password, "password") {
            errors.errors.extend(e.errors);
        }
        if !errors.is_empty() {
            return Err(ApiError::validation(&errors));
        }
        let hash = hash_blocking(password).await?;
        let user = UserInfo {
            name: username.clone(),
            role: Role::Admin,
            enabled: true,
        };
        app.backend.set_user(user, Some(hash)).await?;
        Ok(with_actor(ok(json!({ "created": true })), &username))
    })
    .await
}

/// Shared credential check for login and password change: serialised, rate limited,
/// constant-work (the backend verifies against a dummy hash for unknown users).
async fn check_credentials(
    app: &AppState,
    ip: ClientIp,
    username: &str,
    password: &str,
) -> ApiResult<Option<UserInfo>> {
    let name_key: String = username.to_lowercase().chars().take(64).collect();
    let user_key = format!("u:{name_key}");
    let ip_key = format!("i:{}", rate_limit_key(ip.0));
    let blocked = || {
        app.limiter
            .blocked(&[&user_key, &ip_key])
            .map(|wait| ApiError::too_many_requests(wait.as_secs().max(1)))
    };
    // Rejected before queueing, so a locked-out client cannot pile up on the gate...
    if let Some(err) = blocked() {
        return Err(err);
    }
    let _permit = app
        .login_gate
        .acquire()
        .await
        .map_err(|_| crate::dto::BackendError::Internal("login gate closed".into()))?;
    // ...and checked again once it is our turn: failures recorded while we waited count.
    if let Some(err) = blocked() {
        return Err(err);
    }
    match app.backend.verify_password(username, password).await? {
        Some(user) if user.enabled => {
            app.limiter.clear(&user_key);
            Ok(Some(user))
        }
        _ => {
            app.limiter.record_failure(&[&user_key, &ip_key]);
            Ok(None)
        }
    }
}

fn cookie_header(app: &AppState, token: &str, lifetime: &str) -> HeaderValue {
    let secure = if app.secure { "; Secure" } else { "" };
    let value =
        format!("{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/{lifetime}{secure}");
    // Tokens are base64url, so this cannot fail; an empty value would just not log in.
    HeaderValue::from_str(&value).unwrap_or_else(|_| HeaderValue::from_static(""))
}

/// A browser-session cookie: deliberately without `Max-Age`/`Expires`, so the server-side
/// sliding idle TTL (refreshed by every authenticated request in `SessionStore::lookup`)
/// and the 24 h absolute TTL are the only lifetimes that matter.
fn session_cookie(app: &AppState, token: &str) -> HeaderValue {
    cookie_header(app, token, "")
}

/// Expires the cookie in the browser (logout).
fn cleared_session_cookie(app: &AppState) -> HeaderValue {
    cookie_header(app, "", "; Max-Age=0")
}

async fn login(
    State(app): State<AppState>,
    Extension(ip): Extension<ClientIp>,
    ApiJson(body): ApiJson<Credentials>,
) -> ApiResult {
    let password = Zeroizing::new(body.password);
    let username = body.username;
    let Some(user) = check_credentials(&app, ip, &username, &password).await? else {
        // Same answer for unknown user, wrong password and disabled account.
        return Ok(with_actor(
            ApiError::unauthorized("invalid username or password").into_response(),
            &username,
        ));
    };
    let created = app.sessions.create(user.clone());
    let mut response = ok(json!({ "user": user, "role": user.role, "csrf": created.csrf }));
    response
        .headers_mut()
        .insert(header::SET_COOKIE, session_cookie(&app, &created.token));
    Ok(with_actor(response, &user.name))
}

// ---------------------------------------------------------------------------
// Session endpoints

async fn session_info(Extension(session): Extension<SessionView>) -> Response {
    ok(json!({ "user": session.user, "role": session.user.role, "csrf": session.csrf }))
}

async fn logout(
    State(app): State<AppState>,
    Extension(session): Extension<SessionView>,
) -> Response {
    app.sessions.remove(&session.key);
    let mut response = ok(json!({ "logged_out": true }));
    response
        .headers_mut()
        .insert(header::SET_COOKIE, cleared_session_cookie(&app));
    response
}

#[derive(Deserialize)]
struct PasswordChange {
    current: String,
    new: String,
}

async fn change_password(
    State(app): State<AppState>,
    Extension(session): Extension<SessionView>,
    Extension(ip): Extension<ClientIp>,
    ApiJson(body): ApiJson<PasswordChange>,
) -> ApiResult {
    detached(async move {
        let current = Zeroizing::new(body.current);
        let new = Zeroizing::new(body.new);
        let name = session.user.name.clone();
        let _guard = app.admin_lock.lock().await;
        if check_credentials(&app, ip, &name, &current)
            .await?
            .is_none()
        {
            return Err(ApiError::forbidden("current password is incorrect"));
        }
        check_password_policy(&name, &new, "new").map_err(|e| ApiError::validation(&e))?;
        if *new == *current {
            return Err(ApiError::validation(&ValidationErrors::single(
                "new",
                "must differ from the current password",
            )));
        }
        let hash = hash_blocking(new).await?;
        // Password only: the session's UserInfo may be stale (role changed meanwhile) and
        // must not be written back.
        app.backend.set_password(&name, hash).await?;
        app.sessions.revoke_user(&name, Some(&session.key));
        Ok(ok(json!({ "changed": true })))
    })
    .await
}

// ---------------------------------------------------------------------------
// Read-only system endpoints

async fn board(State(app): State<AppState>) -> ApiResult {
    Ok(ok(app.backend.board().await?))
}

async fn system_status(State(app): State<AppState>) -> ApiResult {
    Ok(ok(app.backend.status().await?))
}

async fn network_status(State(app): State<AppState>) -> ApiResult {
    Ok(ok(app.backend.network_status().await?))
}

async fn wireless_status(State(app): State<AppState>) -> ApiResult {
    Ok(ok(app.backend.wireless_status().await?))
}

async fn dhcp_leases(State(app): State<AppState>) -> ApiResult {
    Ok(ok(app.backend.dhcp_leases().await?))
}

async fn firewall_preview(State(app): State<AppState>) -> ApiResult {
    let text = app.backend.firewall_preview().await?;
    Ok(([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], text).into_response())
}

#[derive(Deserialize)]
struct LogsQuery {
    since: Option<u64>,
    limit: Option<u32>,
}

async fn logs(State(app): State<AppState>, ApiQuery(q): ApiQuery<LogsQuery>) -> ApiResult {
    let limit = q.limit.unwrap_or(DEFAULT_LOG_LIMIT).clamp(1, MAX_LOG_LIMIT);
    let limit = u16::try_from(limit).unwrap_or(500);
    Ok(ok(app.backend.logs(q.since.unwrap_or(0), limit).await?))
}

async fn services(State(app): State<AppState>) -> ApiResult {
    Ok(ok(app.backend.services().await?))
}

// ---------------------------------------------------------------------------
// Configuration

async fn get_config(State(app): State<AppState>) -> ApiResult {
    Ok(ok(app.backend.config().await?))
}

async fn validate_config(State(app): State<AppState>, ApiJson(cfg): ApiJson<Value>) -> ApiResult {
    app.backend
        .validate_config(cfg)
        .await
        .map_err(|e| ApiError::validation(&e))?;
    Ok(ok(json!({ "valid": true })))
}

async fn put_config(
    State(app): State<AppState>,
    Extension(session): Extension<SessionView>,
    ApiJson(cfg): ApiJson<Value>,
) -> ApiResult {
    detached(async move {
        app.backend
            .validate_config(cfg.clone())
            .await
            .map_err(|e| ApiError::validation(&e))?;
        let report = app.backend.save_config(cfg, &session.user.name).await?;
        Ok(ok(report))
    })
    .await
}

// ---------------------------------------------------------------------------
// Actions

async fn service_action(
    State(app): State<AppState>,
    ApiPath((name, action)): ApiPath<(String, String)>,
) -> ApiResult {
    let action = match action.as_str() {
        "restart" => ServiceAction::Restart,
        "reload" => ServiceAction::Reload,
        _ => return Err(ApiError::not_found()),
    };
    let valid_name = !name.is_empty()
        && name.len() <= MAX_SERVICE_NAME_CHARS
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if !valid_name {
        return Err(ApiError::not_found());
    }
    detached(async move {
        app.backend.service_action(&name, action).await?;
        Ok(ok(json!({ "name": name, "action": action })))
    })
    .await
}

async fn reboot(State(app): State<AppState>) -> ApiResult {
    detached(async move {
        app.backend.reboot().await?;
        Ok(ok(json!({ "rebooting": true })))
    })
    .await
}

// ---------------------------------------------------------------------------
// Users

async fn list_users(State(app): State<AppState>) -> ApiResult {
    Ok(ok(app.backend.users().await?))
}

#[derive(Deserialize)]
struct UserUpdate {
    role: Role,
    #[serde(default = "default_true")]
    enabled: bool,
    password: Option<String>,
}

fn default_true() -> bool {
    true
}

/// Fail if removing admin powers from `target` would leave no enabled administrator.
fn ensure_admin_remains(users: &[UserInfo], target: &str) -> ApiResult<()> {
    let others = users
        .iter()
        .any(|u| u.name != target && u.role == Role::Admin && u.enabled);
    if others {
        Ok(())
    } else {
        Err(ApiError::conflict("cannot remove the last administrator"))
    }
}

async fn put_user(
    State(app): State<AppState>,
    Extension(session): Extension<SessionView>,
    ApiPath(name): ApiPath<String>,
    ApiJson(body): ApiJson<UserUpdate>,
) -> ApiResult {
    validate_username(&name).map_err(|e| ApiError::validation(&e))?;
    let is_self = name == session.user.name;
    let drops_admin = body.role != Role::Admin || !body.enabled;
    if is_self && drops_admin {
        return Err(ApiError::conflict(
            "you cannot demote or disable your own account",
        ));
    }
    let password = body.password.map(Zeroizing::new);
    if let Some(pw) = &password {
        check_password_policy(&name, pw, "password").map_err(|e| ApiError::validation(&e))?;
    }
    detached(async move {
        let _guard = app.admin_lock.lock().await;
        let users = app.backend.users().await?;
        let existing = users.iter().find(|u| u.name == name);
        if existing.is_none() && password.is_none() {
            return Err(ApiError::validation(&ValidationErrors::single(
                "password",
                "required when creating a user",
            )));
        }
        if drops_admin && existing.is_some_and(|u| u.role == Role::Admin && u.enabled) {
            ensure_admin_remains(&users, &name)?;
        }
        let hash = match password {
            Some(pw) => Some(hash_blocking(pw).await?),
            None => None,
        };
        let invalidates_sessions =
            existing.is_some_and(|u| u.role != body.role) || drops_admin || hash.is_some();
        let created = existing.is_none();
        let info = UserInfo {
            name: name.clone(),
            role: body.role,
            enabled: body.enabled,
        };
        app.backend.set_user(info.clone(), hash).await?;
        if invalidates_sessions && !created {
            let keep = is_self.then_some(&session.key);
            app.sessions.revoke_user(&name, keep);
        }
        let mut response = ok(info);
        if created {
            *response.status_mut() = StatusCode::CREATED;
        }
        Ok(response)
    })
    .await
}

async fn delete_user(
    State(app): State<AppState>,
    Extension(session): Extension<SessionView>,
    ApiPath(name): ApiPath<String>,
) -> ApiResult {
    if name == session.user.name {
        return Err(ApiError::conflict("you cannot delete your own account"));
    }
    detached(async move {
        let _guard = app.admin_lock.lock().await;
        let users = app.backend.users().await?;
        let Some(target) = users.iter().find(|u| u.name == name) else {
            return Err(ApiError::not_found());
        };
        if target.role == Role::Admin && target.enabled {
            ensure_admin_remains(&users, &name)?;
        }
        app.backend.delete_user(&name).await?;
        app.sessions.revoke_user(&name, None);
        Ok(ok(json!({ "deleted": name })))
    })
    .await
}

// ---------------------------------------------------------------------------
// Backup / restore

async fn backup_config(State(app): State<AppState>) -> ApiResult {
    let bytes = app.backend.backup().await?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"ferritewrt-config-backup.toml\"",
            ),
        ],
        bytes,
    )
        .into_response())
}

async fn restore_config(
    State(app): State<AppState>,
    Extension(session): Extension<SessionView>,
    body: Bytes,
) -> ApiResult {
    if body.is_empty() {
        return Err(ApiError::bad_request("empty request body"));
    }
    detached(async move {
        // Restore replaces the users: serialise with user management so it cannot
        // interleave with the last-admin checks of put_user/delete_user.
        let _guard = app.admin_lock.lock().await;
        let report = app
            .backend
            .restore(body.to_vec(), &session.user.name)
            .await?;
        // Users and roles may have changed: force everyone to log in again.
        app.sessions.clear();
        Ok(ok(report))
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(name: &str, role: Role, enabled: bool) -> UserInfo {
        UserInfo {
            name: name.into(),
            role,
            enabled,
        }
    }

    #[test]
    fn last_admin_protection() {
        let users = vec![
            u("a", Role::Admin, true),
            u("v", Role::Viewer, true),
            u("d", Role::Admin, false),
        ];
        assert!(ensure_admin_remains(&users, "a").is_err());
        let users = vec![u("a", Role::Admin, true), u("b", Role::Admin, true)];
        assert!(ensure_admin_remains(&users, "a").is_ok());
    }

    #[tokio::test]
    async fn locked_out_client_is_rejected_before_queueing_on_the_login_gate() {
        use std::sync::Arc;
        use std::time::Duration;

        use crate::server::ServerConfig;
        use crate::session::RateLimiter;

        let dir = tempfile::tempdir().unwrap();
        let cfg = ServerConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            session_ttl: Duration::from_mins(30),
            backend: Arc::new(crate::mock::MockBackend::new()),
            ui_enabled: false,
            ui_dir: None,
            audit_log_path: dir.path().join("audit.log"),
        };
        let (_, app) = crate::server::build(&cfg);
        let ip = ClientIp("192.168.8.9".parse().unwrap());
        let ip_key = format!("i:{}", rate_limit_key(ip.0));
        for _ in 0..RateLimiter::MAX_FAILURES {
            app.limiter.record_failure(&["u:admin", &ip_key]);
        }
        // Another login is in flight and holds the gate.
        let _busy = app.login_gate.acquire().await.unwrap();
        let attempt = tokio::time::timeout(
            Duration::from_secs(2),
            check_credentials(&app, ip, "admin", "whatever"),
        )
        .await
        .expect("a blocked client must not wait for the login gate");
        assert_eq!(attempt.unwrap_err().status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn username_rules() {
        assert!(validate_username("admin").is_ok());
        assert!(validate_username("a.b_c-9").is_ok());
        assert!(validate_username("").is_err());
        assert!(validate_username("has space").is_err());
        assert!(validate_username(&"x".repeat(33)).is_err());
        assert!(validate_username("../etc").is_err());
    }
}
