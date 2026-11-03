//! Static web UI hosting: embedded `ui/` directory (or a directory on disk for
//! development), SPA fallback for extension-less routes, content-hash `ETag`s.

use std::fmt::Write;
use std::path::{Component, Path, PathBuf};

use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::Response;
use include_dir::{Dir, include_dir};
use sha2::{Digest, Sha256};

static EMBEDDED: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/ui");

const INDEX: &str = "index.html";

/// Shown when the build embeds no `index.html`.
const PLACEHOLDER: &str = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<title>ferritewrt</title></head><body><h1>ferritewrt</h1>\
<p>The web UI is not bundled in this build. The API is available under /api/v1.</p>\
</body></html>";

/// Where UI files come from.
#[derive(Debug, Clone)]
pub enum UiSource {
    /// Compiled into the binary.
    Embedded,
    /// Read from a directory at request time (development convenience).
    Disk(PathBuf),
}

impl UiSource {
    async fn read(&self, rel: &str) -> Option<Bytes> {
        match self {
            Self::Embedded => EMBEDDED
                .get_file(rel)
                .map(|f| Bytes::from_static(f.contents())),
            Self::Disk(base) => {
                let path = base.join(rel);
                if !tokio::fs::metadata(&path).await.ok()?.is_file() {
                    return None;
                }
                tokio::fs::read(&path).await.ok().map(Bytes::from)
            }
        }
    }

    /// Respond to `GET <uri_path>`: the file if it exists, otherwise `index.html`
    /// (single-page-app routing) for extension-less paths, otherwise 404. A missing
    /// `/js/app.js` must not come back as HTML with status 200. Without any
    /// `index.html` a built-in placeholder is shown.
    pub async fn respond(&self, uri_path: &str, request_headers: &HeaderMap) -> Response {
        match normalize(uri_path) {
            Some(rel) if rel != INDEX => {
                if let Some(body) = self.read(&rel).await {
                    return build_response(&rel, body, request_headers);
                }
            }
            Some(_) => return self.index(request_headers).await,
            None => {}
        }
        if has_extension(uri_path) {
            let mut response = Response::new(Body::empty());
            *response.status_mut() = StatusCode::NOT_FOUND;
            return response;
        }
        self.index(request_headers).await
    }

    async fn index(&self, request_headers: &HeaderMap) -> Response {
        let body = self
            .read(INDEX)
            .await
            .unwrap_or_else(|| Bytes::from_static(PLACEHOLDER.as_bytes()));
        build_response(INDEX, body, request_headers)
    }
}

/// Map a URL path to a safe relative file path; `None` for anything suspicious.
fn normalize(uri_path: &str) -> Option<String> {
    let trimmed = uri_path.trim_start_matches('/');
    if trimmed.is_empty() {
        return Some(INDEX.to_owned());
    }
    if trimmed.contains(['\\', '\0', ':']) {
        return None;
    }
    let mut parts = Vec::new();
    for component in Path::new(trimmed).components() {
        match component {
            Component::Normal(p) => {
                let p = p.to_str()?;
                if p.starts_with('.') {
                    return None;
                }
                parts.push(p);
            }
            _ => return None,
        }
    }
    Some(parts.join("/"))
}

/// Does the last path segment look like a file name (`app.js`, but not `.hidden` or `route`)?
fn has_extension(uri_path: &str) -> bool {
    let last = uri_path.rsplit('/').next().unwrap_or_default();
    last.rsplit_once('.')
        .is_some_and(|(stem, ext)| !stem.is_empty() && !ext.is_empty())
}

fn content_type(rel: &str) -> HeaderValue {
    let mime = mime_guess::from_path(rel).first_or_octet_stream();
    let textual = mime.type_() == mime_guess::mime::TEXT
        || matches!(mime.subtype().as_str(), "javascript" | "json" | "xml")
        || mime
            .suffix()
            .is_some_and(|s| s == mime_guess::mime::XML || s == mime_guess::mime::JSON);
    let value = if textual {
        format!("{mime}; charset=utf-8")
    } else {
        mime.to_string()
    };
    HeaderValue::from_str(&value)
        .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"))
}

fn etag(body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    let hex = digest.iter().take(8).fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    });
    format!("\"{hex}\"")
}

/// `If-None-Match` evaluation (RFC 9110 weak comparison): `*` matches any current
/// representation, `W/` prefixes are ignored.
fn matches_if_none_match(value: &str, tag: &str) -> bool {
    value
        .split(',')
        .map(str::trim)
        .any(|t| t == "*" || t.strip_prefix("W/").unwrap_or(t) == tag)
}

/// Assets are revalidated on every load (`no-cache` + `ETag`), so an upgrade is picked up
/// immediately while unchanged files still cost only a 304.
fn build_response(rel: &str, body: Bytes, request_headers: &HeaderMap) -> Response {
    let tag = etag(&body);
    let not_modified = request_headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| matches_if_none_match(v, &tag));
    let mut response = if not_modified {
        let mut r = Response::new(Body::empty());
        *r.status_mut() = StatusCode::NOT_MODIFIED;
        r
    } else {
        let mut r = Response::new(Body::from(body));
        r.headers_mut()
            .insert(header::CONTENT_TYPE, content_type(rel));
        r
    };
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    if let Ok(v) = HeaderValue::from_str(&tag) {
        headers.insert(header::ETAG, v);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_paths() {
        assert_eq!(normalize("/").as_deref(), Some("index.html"));
        assert_eq!(normalize("/app.js").as_deref(), Some("app.js"));
        assert_eq!(normalize("/a/b.css").as_deref(), Some("a/b.css"));
        assert_eq!(normalize("/../etc/passwd"), None);
        assert_eq!(normalize("/a/../b"), None);
        assert_eq!(normalize("/.gitkeep"), None);
        assert_eq!(normalize("/a\\b"), None);
        assert_eq!(normalize("/C:/x"), None);
    }

    #[test]
    fn content_types() {
        assert_eq!(content_type("index.html"), "text/html; charset=utf-8");
        assert_eq!(content_type("styles.css"), "text/css; charset=utf-8");
        assert!(
            content_type("app.js")
                .to_str()
                .unwrap()
                .ends_with("; charset=utf-8")
        );
        assert_eq!(content_type("logo.png"), "image/png");
        assert_eq!(content_type("blob.zzzz"), "application/octet-stream");
    }

    #[tokio::test]
    async fn disk_source_serves_files_and_falls_back() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), "<p>idx</p>").unwrap();
        std::fs::write(dir.path().join("app.js"), "let a=1;").unwrap();
        let src = UiSource::Disk(dir.path().to_path_buf());
        let h = HeaderMap::new();

        let r = src.respond("/app.js", &h).await;
        assert_eq!(r.headers()[header::CACHE_CONTROL], "no-cache");
        let tag = r.headers()[header::ETAG].clone();

        let r = src.respond("/nope/route", &h).await;
        assert_eq!(r.headers()[header::CACHE_CONTROL], "no-cache");
        let body = axum::body::to_bytes(r.into_body(), 1024).await.unwrap();
        assert_eq!(&body[..], b"<p>idx</p>");

        let mut h2 = HeaderMap::new();
        h2.insert(header::IF_NONE_MATCH, tag);
        let r = src.respond("/app.js", &h2).await;
        assert_eq!(r.status(), StatusCode::NOT_MODIFIED);
    }

    #[tokio::test]
    async fn missing_assets_are_404_but_extensionless_routes_get_index() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), "<p>idx</p>").unwrap();
        let src = UiSource::Disk(dir.path().to_path_buf());
        let h = HeaderMap::new();
        for path in ["/js/missing.js", "/a/b.css", "/..%2f..%2fCargo.toml"] {
            let r = src.respond(path, &h).await;
            assert_eq!(r.status(), StatusCode::NOT_FOUND, "{path}");
        }
        for path in ["/", "/index.html", "/network/lan", "/v1.2/", "/.hidden"] {
            let r = src.respond(path, &h).await;
            assert_eq!(r.status(), StatusCode::OK, "{path}");
        }
    }

    #[test]
    fn if_none_match_handles_star_weak_and_lists() {
        let tag = "\"abc\"";
        assert!(matches_if_none_match("*", tag));
        assert!(matches_if_none_match("W/\"abc\"", tag));
        assert!(matches_if_none_match("\"x\", W/\"abc\"", tag));
        assert!(!matches_if_none_match("\"abd\"", tag));
        assert!(!matches_if_none_match("W/\"abd\", \"x\"", tag));
    }

    #[tokio::test]
    async fn conditional_requests_with_star_and_weak_tags_get_304() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.js"), "let a=1;").unwrap();
        let src = UiSource::Disk(dir.path().to_path_buf());
        let tag = src.respond("/app.js", &HeaderMap::new()).await.headers()[header::ETAG]
            .to_str()
            .unwrap()
            .to_owned();
        for value in ["*".to_owned(), format!("W/{tag}")] {
            let mut h = HeaderMap::new();
            h.insert(header::IF_NONE_MATCH, value.parse().unwrap());
            let r = src.respond("/app.js", &h).await;
            assert_eq!(r.status(), StatusCode::NOT_MODIFIED, "{value}");
            assert_eq!(r.headers()[header::CACHE_CONTROL], "no-cache");
        }
    }
    #[tokio::test]
    async fn missing_index_gives_placeholder() {
        let dir = tempfile::tempdir().unwrap();
        let src = UiSource::Disk(dir.path().to_path_buf());
        let r = src.respond("/", &HeaderMap::new()).await;
        assert_eq!(r.status(), StatusCode::OK);
        let body = axum::body::to_bytes(r.into_body(), 4096).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains("not bundled"));
    }
}
