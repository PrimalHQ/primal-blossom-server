use axum::extract::Query;
pub use axum::{
    extract::{Extension, Path},
    http::{header, Response, StatusCode},
    routing::{options, get, put},
    Router,
};
pub use axum::{
    body::Bytes,
    response::IntoResponse,
    Json,
};

pub use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
pub use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};
pub use std::sync::Arc;

pub use std::env;

pub use hex::FromHex;
pub use sqlx::PgPool;
pub use sqlx::pool::PoolOptions;

pub use hex;
pub use sha2::Digest;

pub use std::str::FromStr;

pub use nostr_sdk::prelude::{PublicKey, Event, JsonUtil};

pub use serde_json::Value;
pub use serde_json::json;

pub use clap::Parser;

pub use dashmap::DashMap;

// ------------------ log ---------------------

pub fn log(s: String) {
    // return;
    println!("{} [{}]  {}", 
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S.%6f"), 
        std::process::id(), 
        s);
}

#[macro_export]
macro_rules! log {
    // match: log!( "foo" )
    ($msg:expr) => {
        $crate::log(format!($msg))
    };
    // match: log!( "foo {} {}", a, b )
    ($fmt:expr, $($arg:tt)+) => {
        $crate::log(format!($fmt, $($arg)+))
    };
}

pub fn logerr<T>(e: T)
where
    T: std::fmt::Debug,
{
    log!("{e:?}");
}

pub fn loge<T, R>(res: R) -> impl Fn(T) -> R
where
    T: std::fmt::Debug,
    R: std::clone::Clone
{
    move |e: T| {
        log!("{e:?}");
        res.clone()
    }
}

pub trait ResultLogErr<T, E, R> {
    fn map_log_err(self, r: R) -> Result<T, R>;
}

impl<T, E, R> ResultLogErr<T, E, R> for Result<T, E>
where
    E: std::fmt::Debug,
    R: std::clone::Clone
{
    fn map_log_err(self, r: R) -> Result<T, R> {
        self.map_err(|e| {
            log!("{e:?}");
            r
        })
    }
}

// ------------------ cli ---------------------

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[arg(long)]
    pub config_file: Option<String>,
}

// ------------------ main ---------------------

use serde::Deserialize;

#[derive(Debug,Clone,Deserialize)]
pub struct Config {
    pub port: u16,
    pub base_url: String,
    pub media_server_url: String,
    pub proxy: Option<String>,
    pub binary_data_cache_dir: String,
    pub cache_database_url: String,
    pub membership_database_url: String,
    pub local_storages: HashMap<String, String>,
    pub sandboxing: bool,
}

#[derive(Debug,Clone)]
pub struct State {
    pub cache_pool: PgPool,
    pub membership_pool: PgPool,
    pub exiftool_path: OsString,
    pub ffmpeg_path: OsString,
    pub cache: Arc<DashMap<Vec<u8>, Option<Upload>>>,
}

use std::future::Future;

pub async fn main_1<H, Fut>(my_main: H) -> anyhow::Result<()>
where
  H: Fn(Config, State) -> Fut + Send + Sync + 'static,
  Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
{
    let cli = Cli::parse();

    let config_file = cli.config_file.or(env::var("CONFIG_FILE").ok()).expect("config file is required");
    let config_str = tokio::fs::read_to_string(config_file).await.expect("config file read error");
    let config: Config = serde_json::from_str(&config_str).expect("config file parse error");

    let state = State {
        cache_pool: PoolOptions::new()
            .max_connections(10)
            .min_connections(1)
            .connect(&config.cache_database_url).await?,
        membership_pool: PoolOptions::new()
            .max_connections(10)
            .min_connections(1)
            .connect(&config.membership_database_url).await?,
        exiftool_path: OsString::from(which::which("exiftool").unwrap().to_string_lossy().into_owned()),
        ffmpeg_path: OsString::from(which::which("ffmpeg").unwrap().to_string_lossy().into_owned()),
        cache: Arc::new(DashMap::new()),
    };

    my_main(config, state).await
}

pub fn parse_sha256_from_path(path: &str) -> Result<Vec<u8>, (StatusCode, String)> {
    let id_ext = path.trim_start_matches('/');
    let id = if let Some(idx) = id_ext.find('.') {
        &id_ext[..idx]
    } else {
        id_ext
    };
    match hex::decode(id) {
        Ok(sha256) => Ok(sha256),
        Err(_) => Err((StatusCode::BAD_REQUEST, "invalid sha256".to_string())),
    }
}

#[derive(sqlx::FromRow)]
#[derive(Debug)]
pub struct BlobRecord {
    media_url: String,
    content_type: String,
    size: i64,
}

pub async fn extract_blob_record(state: &State, path: &str) -> Result<Option<BlobRecord>, (StatusCode, String)> {
    let sha256 = parse_sha256_from_path(path)?;

    let b = find_blob(state, sha256).await?;

    if let Some(b) = b {
        return Ok(Some(BlobRecord {
            media_url: b.media_url,
            content_type: b.mimetype,
            size: b.size,
        }));
    }

    Err((StatusCode::NOT_FOUND, "not found".to_string()))
}

fn decode_b64(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, s)
}

pub fn check_action(
    headers: &axum::http::HeaderMap,
    action: &str,
    x_tag_hash: Option<Vec<u8>>,
) -> Result<Event, (StatusCode, String)> {
    // 1) get the header
    let auth = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or((StatusCode::BAD_REQUEST, "missing auth event".to_string()))?;

    // 2) must be "Nostr <base64>"
    let parts: Vec<&str> = auth.split_whitespace().collect();
    if parts.len() != 2 {
        return Err((StatusCode::BAD_REQUEST, "missing auth event".to_string()));
    }
    if parts[0] != "Nostr" {
        return Err((StatusCode::BAD_REQUEST, "invalid auth event".to_string()));
    }

    // 3) base64 decode + JSON parse
    // let raw = base64::decode(parts[1])
    let raw = decode_b64(parts[1])
        .map_log_err((StatusCode::BAD_REQUEST, "invalid base64 for auth event".to_string()))?;
    let event = Event::from_json(&raw)
        .map_log_err((StatusCode::BAD_REQUEST, "invalid auth event".to_string()))?;

    // 4) verify signature & kind
    event.verify().map_log_err((StatusCode::UNAUTHORIZED, "auth event verification failed".to_string()))?;
    if event.kind != nostr_sdk::Kind::Custom(24242) {
        return Err((StatusCode::UNAUTHORIZED, "wrong kind in auth event".to_string()));
    }

    // 5) walk tags
    let now = chrono::Utc::now().timestamp();
    let mut action_ok = false;
    let mut x_tag_ok = x_tag_hash.is_none();

    for tag in event.tags.iter() {
        let fields = tag.clone().to_vec();
        if fields.len() < 2 {
            continue;
        }
        match fields[0].as_str() {
            // expiration: must be in the future
            "expiration" => {
                let exp = fields[1]
                    .parse::<i64>()
                    .map_log_err((StatusCode::BAD_REQUEST, "invalid expiration tag".to_string()))?;
                if exp <= now {
                    return Err((StatusCode::UNAUTHORIZED, "auth event expired".to_string()));
                }
            }
            // t: action
            "t" => {
                if fields[1] == action {
                    action_ok = true;
                }
            }
            // x: hex‐encoded custom tag
            "x" => {
                if let Some(ref x_tag_hash) = x_tag_hash {
                    let x = hex::decode(&fields[1])
                        .map_log_err((StatusCode::BAD_REQUEST, "invalid x tag".to_string()))?;
                    if x.as_slice() == x_tag_hash {
                        x_tag_ok = true;
                    }
                }
            }
            _ => {}
        }
    }

    if !action_ok {
        return Err((StatusCode::UNAUTHORIZED, "invalid action in auth event".to_string()));
    }
    if !x_tag_ok {
        return Err((StatusCode::UNAUTHORIZED, "invalid x tag".to_string()));
    }

    Ok(event)
}

pub fn make_response(
    status: StatusCode,
    content_type: &str,
    body: &str,
    extra_headers: Vec<(&str, &str)>
) -> Response<axum::body::Body> {
    let mut hdrs = HashMap::new();
    hdrs.insert("Access-Control-Allow-Origin".to_string(), "*".to_string());
    hdrs.insert("Access-Control-Allow-Methods".to_string(), "*".to_string());
    hdrs.insert(header::CONTENT_TYPE.to_string(), content_type.to_string());
    hdrs.insert(header::CONTENT_LENGTH.to_string(), body.len().to_string());
    for (name, value) in extra_headers.iter() {
        hdrs.insert(name.to_string(), value.to_string());
    }
    let mut builder = Response::builder().status(status);
    for (name, value) in hdrs.iter() {
        builder = builder.header(name, value);
    }
    builder.body(axum::body::Body::from(body.to_string())).unwrap()
}

pub fn get_user_agent(headers: &axum::http::HeaderMap) -> String {
    headers.get("User-Agent").and_then(|v| v.to_str().ok()).unwrap_or("unknown").to_string()
}

pub async fn options_handler(
    headers: axum::http::HeaderMap,
    Extension(_config): Extension<Config>,
    Extension(_state): Extension<State>,
    Path(path): Path<String>,
) -> Result<Response<axum::body::Body>, (StatusCode, String)> {
    log!("OPTIONS {path} | {}", get_user_agent(&headers));
    Ok(make_response(StatusCode::OK, "text/plain", "ok", vec![
        ("Access-Control-Allow-Headers", "Authorization, *"),
        ("Access-Control-Allow-Methods", "GET, PUT, DELETE"),
    ]))
}

pub async fn head_handler(
    headers: axum::http::HeaderMap,
    Extension(_config): Extension<Config>,
    Extension(state): Extension<State>,
    Path(path): Path<String>,
) -> Result<Response<axum::body::Body>, (StatusCode, String)> {
    log!("HEAD {path} | {}", get_user_agent(&headers));
    
    if path == "upload" || path == "media" {
        #[cfg(not(feature = "media-processing"))]
        if path == "media" {
            return Err((StatusCode::NOT_FOUND, "media upload is not supported".to_string()));
        }

        let sha256 = match headers.get("X-SHA-256") {
            Some(value) => match hex::decode(value) {
                Ok(bytes) => bytes,
                Err(_) => return Err((axum::http::StatusCode::UNAUTHORIZED, "Invalid X-SHA-256 header".to_string())),
            },
            None => return Err((axum::http::StatusCode::UNAUTHORIZED, "X-SHA-256 request header is missing".to_string())),
        };

        check_action(&headers, "upload", Some(sha256))?;

        Ok(make_response(StatusCode::OK, "text/plain", "ok", vec![]))
    } else {
        if let Some(r) = extract_blob_record(&state, &path).await? {
            Ok(make_response(StatusCode::OK, r.content_type.as_str(), "", vec![
                    (header::CONTENT_LENGTH.as_str(), &r.size.to_string().as_str()),
            ]))
        } else {
            Err((StatusCode::NOT_FOUND, "not found".to_string()))
        }
    }
}

pub async fn welcome_page_handler(
    headers: axum::http::HeaderMap,
    Extension(_config): Extension<Config>,
    Extension(_state): Extension<State>,
) -> Result<Response<axum::body::Body>, (StatusCode, String)> {
    log!("GET / | {}", get_user_agent(&headers));
    Ok(make_response(StatusCode::OK, "text/plain", "Welcome to Primal Blossom server. Implemented: BUD-01, BUD-02, BUD-04, BUD-05", vec![]))
}

pub async fn get_handler(
    headers: axum::http::HeaderMap,
    Extension(config): Extension<Config>,
    Extension(state): Extension<State>,
    Path(path): Path<String>,
) -> Result<Response<axum::body::Body>, (StatusCode, String)> {
    log!("GET {path} | {}", get_user_agent(&headers));
    
    let rec = extract_blob_record(&state, &path).await?;

    if let Some(r) = rec {
        Ok(Response::builder()
            .status(StatusCode::FOUND)
            .header(header::LOCATION, r.media_url)
            .header(header::CONTENT_TYPE, r.content_type)
            .header("Access-Control-Allow-Methods", "*")
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Headers", "*")
            .body(axum::body::Body::empty())
            .unwrap())
    } else {
        Err((StatusCode::NOT_FOUND, "not found".to_string()))
    }
}

pub async fn get_list_handler(
    headers: axum::http::HeaderMap,
    Extension(config): Extension<Config>,
    Extension(state): Extension<State>,
    Path(path): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response<axum::body::Body>, (StatusCode, String)> {
    log!("GET /list/{path} | {}", get_user_agent(&headers));
    
    let pk = PublicKey::parse(&path).map_log_err((StatusCode::BAD_REQUEST, "invalid pubkey".to_string()))?;
    let e = check_action(&headers, "list", None)?;
    
    if e.pubkey != pk {
        return Err((StatusCode::UNAUTHORIZED, "invalid pubkey".to_string()));
    }

    let since = params.get("since").and_then(|v| v.parse::<i64>().ok()).unwrap_or(0);
    let until = params.get("until").and_then(|v| v.parse::<i64>().ok()).unwrap_or(chrono::Utc::now().timestamp());

    let mut res = vec![];
    for r in sqlx::query!(
        r#"
        SELECT mimetype, created_at, path, size, sha256
          FROM media_uploads
         WHERE pubkey = $1
           AND created_at >= $2
           AND created_at <= $3
           AND media_block_id IS null
        "#,
        &pk.to_bytes(),
        since,
        until,
    ).fetch_all(&state.membership_pool).await.map_log_err((StatusCode::INTERNAL_SERVER_ERROR, "db error".to_string()))? {
        let ext = MIMETYPE_EXT.get(&r.mimetype.as_str()).unwrap_or(&"");
        let sha256_hex = hex::encode(&r.sha256.ok_or((StatusCode::INTERNAL_SERVER_ERROR, "invalid sha256".to_string()))?);
        res.push(json!({
                    "url": format!("{}/{}{}", config.base_url, sha256_hex, ext),
                    "sha256": sha256_hex,
                    "size": r.size,
                    "type": r.mimetype,
                    "uploaded": r.created_at,
        }));
    }
    Ok(make_response(StatusCode::OK, "application/json", 
            serde_json::to_string(&res).map_log_err((StatusCode::INTERNAL_SERVER_ERROR, "json error".to_string()))?.as_str(), 
            vec![]))
}

pub async fn delete_handler(
    headers: axum::http::HeaderMap,
    Extension(config): Extension<Config>,
    Extension(state): Extension<State>,
    Path(path): Path<String>,
) -> Result<Response<axum::body::Body>, (StatusCode, String)> {
    log!("DELETE {path} | {}", get_user_agent(&headers));
    
    let sha256 = parse_sha256_from_path(path.as_str())?;

    let b = find_blob(&state, sha256.clone()).await?;

    if let Some(b) = b {
        let e = check_action(&headers, "delete", Some(b.sha256))?;
        log!("DELETE pubkey: {}", e.pubkey.to_hex());

        if let Some(_) = sqlx::query!(
            r#"
            SELECT 1 as one
              FROM media_uploads
             WHERE sha256 = $1
               AND pubkey = $2
               AND media_block_id IS NULL
             LIMIT 1
            "#,
            sha256,
            &e.pubkey.to_bytes(),
        ).fetch_optional(&state.membership_pool).await.map_log_err((StatusCode::INTERNAL_SERVER_ERROR, "db error".to_string()))? {
            cfg_if::cfg_if! {
                if #[cfg(feature = "media-processing")] {
                    let blossom_url = format!("{}/{}", config.base_url, path);
                    let nid = schedule_processing_node(
                        &state, 
                        "PrimalServer.InternalServices", 
                        "purge_media_",
                        json!({
                            "_ty": "Tuple",
                            "_v": [
                            {"_ty": "PubKeyId", "_v": e.pubkey.to_hex()},
                            blossom_url,
                            ],
                        }), 
                        json!({
                            "extra": {
                                "_ty": "NamedTuple",
                                "_v": {
                                    "initiator_pubkey": {
                                        "_ty": "PubKeyId",
                                        "_v": e.pubkey.to_hex()
                                    }
                                }
                            },
                            "reason": format!("delete from {}", config.base_url),
                        }),
                        ).await.map_log_err((StatusCode::INTERNAL_SERVER_ERROR, "purge_media_ failed".to_string()))?;

                    wait_processing_node(&state, nid).await.map_log_err((StatusCode::INTERNAL_SERVER_ERROR, "wait_processing_node failed".to_string()))?;
                } else {
                    let mut tx = state.membership_pool.begin().await.map_log_err((StatusCode::INTERNAL_SERVER_ERROR, "db error".to_string()))?;
                    let ulpkcnt  = sqlx::query!(r#"select count(1) as cnt from media_uploads where sha256 = $1 and pubkey = $2"#, sha256, &e.pubkey.to_bytes()).fetch_one(&mut *tx).await.map_log_err((StatusCode::INTERNAL_SERVER_ERROR, "db error".to_string()))?.cnt;
                    let ulallcnt = sqlx::query!(r#"select count(1) as cnt from media_uploads where sha256 = $1"#, sha256).fetch_one(&mut *tx).await.map_log_err((StatusCode::INTERNAL_SERVER_ERROR, "db error".to_string()))?.cnt;
                    sqlx::query!(r#"DELETE FROM media_uploads WHERE sha256 = $1 and pubkey = $2"#, sha256, &e.pubkey.to_bytes()).execute(&state.membership_pool).await.map_log_err((StatusCode::INTERNAL_SERVER_ERROR, "db error".to_string()))?;
                    if let (Some(ulpkcnt), Some(ulallcnt)) = (ulpkcnt, ulallcnt) {
                        if ulpkcnt != 0 && ulpkcnt == ulallcnt {
                            sqlx::query!(r#"DELETE FROM media_storage WHERE sha256 = $1"#, sha256).execute(&state.membership_pool).await.map_log_err((StatusCode::INTERNAL_SERVER_ERROR, "db error".to_string()))?;
                        }
                    }
                    tx.commit().await.map_log_err((StatusCode::INTERNAL_SERVER_ERROR, "db error".to_string()))?;
                }
            }

            return Ok(make_response(StatusCode::OK, "text/plain", "ok", vec![]))
        }
    }

    Err((StatusCode::NOT_FOUND, "not found".to_string()))
}

pub use sqlx::Transaction;
pub use sqlx::Postgres;
pub use sqlx::Executor;

pub async fn put_handler(
    headers: axum::http::HeaderMap,
    Extension(config): Extension<Config>,
    Extension(state): Extension<State>,
    Path(path): Path<String>,
    data: Bytes
) -> Result<Response<axum::body::Body>, (StatusCode, String)> {
    log!("PUT {path}: got {} bytes | {}", data.len(), get_user_agent(&headers));

    if path == "mirror" {
        let req = serde_json::from_slice::<Value>(&data).map_log_err((StatusCode::BAD_REQUEST, "invalid json".to_string()))?;
        let url = req.get("url").ok_or((StatusCode::BAD_REQUEST, "missing url".to_string()))?.as_str().ok_or((StatusCode::BAD_REQUEST, "invalid url".to_string()))?;
        let parsed_url = reqwest::Url::parse(&url).map_log_err((StatusCode::BAD_REQUEST, "invalid url".to_string()))?;
        let sha256 = parse_sha256_from_path(parsed_url.path())?;
        let e = check_action(&headers, "upload", Some(sha256.clone()))?;
        log!("PUT {} pubkey: {}", hex::encode(&sha256), e.pubkey.to_hex());

        let data = download(url, &config).await.map_log_err((StatusCode::BAD_REQUEST, "download error".to_string()))?;
        let (r, burl) = import_blob(&e, &data.to_vec(), &config, &state).await.map_log_err((StatusCode::INTERNAL_SERVER_ERROR, "blob import error".to_string()))?;

        #[cfg(feature = "media-processing")]
        {
            let _nid = schedule_media_processing(&config, &state, e.pubkey, data, sha256, burl).await.map_log_err((StatusCode::INTERNAL_SERVER_ERROR, "scheduling media processing failed".to_string()))?;
            // wait_processing_node(&config, nid).await.map_log_err((StatusCode::INTERNAL_SERVER_ERROR, "wait_processing_node failed".to_string()))?;
        }

        Ok(make_response(StatusCode::OK, "application/json", 
                serde_json::to_string(&r).map_log_err((StatusCode::INTERNAL_SERVER_ERROR, "json error".to_string()))?.as_str(), 
                vec![]))

    } else if path == "upload" || path == "media" {
        #[cfg(not(feature = "media-processing"))]
        if path == "media" {
            return Err((StatusCode::BAD_REQUEST, "media upload is not supported".to_string()));
        }

        let data = data.to_vec();
        let sha256 = sha2::Sha256::digest(&data).to_vec();
        let sha256_hex = hex::encode(&sha256);
        let e = check_action(&headers, "upload", Some(sha256.clone()))?;
        log!("PUT {} pubkey: {}", sha256_hex, e.pubkey.to_hex());

        let data = if path == "media" {
            let data2 = strip_metadata(&config, &state, data).await.map_log_err((StatusCode::INTERNAL_SERVER_ERROR, "metadata stripping error".to_string()))?;
            sqlx::query!(r#"INSERT INTO media_metadata_stripping VALUES ($1, $2, now(), $3)"#, 
                &sha256,
                &sha2::Sha256::digest(&data2).to_vec(),
                json!({"mod": "primal_blossom_server", "func": "put_handler", "pubkey": e.pubkey.to_hex()})
            ).execute(&state.cache_pool).await.map_log_err((StatusCode::INTERNAL_SERVER_ERROR, "db error".to_string()))?;
            data2
        } else {
            data
        };
        let (r, burl) = import_blob(&e, &data, &config, &state).await.map_log_err((StatusCode::INTERNAL_SERVER_ERROR, "blob import error".to_string()))?;

        #[cfg(feature = "media-processing")]
        {
            let _nid = schedule_media_processing(&config, &state, e.pubkey, data, sha256, burl).await.map_log_err((StatusCode::INTERNAL_SERVER_ERROR, "scheduling media processing failed".to_string()))?;
            // wait_processing_node(&config, nid).await.map_log_err((StatusCode::INTERNAL_SERVER_ERROR, "wait_processing_node failed".to_string()))?;
        }

        Ok(make_response(StatusCode::OK, "application/json", 
                serde_json::to_string(&r).map_log_err((StatusCode::INTERNAL_SERVER_ERROR, "json error".to_string()))?.as_str(), 
                vec![]))
    } else {
        Err((StatusCode::NOT_FOUND, "not found".to_string()))
    }
}

pub async fn import_blob(e: &Event, data: &Vec<u8>, config: &Config, state: &State) -> Result<(Value, String), String> {
    let sha256 = sha2::Sha256::digest(&data).to_vec();
    let sha256_hex = hex::encode(&sha256);
    log!("import_blob: sha256: {sha256_hex}");

    let size = data.len() as i64;
    let content_type = parse_mimetype(&data.to_vec()).await.map_log_err("parsing mimetype failed".to_string())?;
    let ext = MIMETYPE_EXT.get(&content_type.as_str()).unwrap_or(&"");

    let t = chrono::Local::now().timestamp() as i64;

    let subdir = format!(
        "/uploads2/{}/{}/{}",
        &sha256_hex[0..1],
        &sha256_hex[1..3],
        &sha256_hex[3..5],
    );

    let key = json!({"type": "member_upload", "pubkey": e.pubkey.to_hex(), "sha256": sha256_hex});
    let h = hex::encode(sha2::Sha256::digest(key.to_string().as_bytes()).to_vec());

    for (host, hostdir) in config.local_storages.iter() {
        let dir = format!("{hostdir}{subdir}");
        tokio::fs::create_dir_all(&dir).await.map_log_err("create_dir_all failed".to_string())?;
        let path = format!("{dir}/{sha256_hex}{ext}");

        if !tokio::fs::metadata(&path).await.is_ok() {
            let path_tmp = format!("{path}.tmp");
            {
                let mut file = tokio::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(&path_tmp)
                    .await
                    .map_log_err("file creating failed".to_string())?;
                file.write_all(&data).await.map_log_err("file writing failed".to_string())?;
            }
            tokio::fs::rename(&path_tmp, &path).await.map_log_err("file renaming failed".to_string())?;
            log!("{path_tmp} -> {path}: ok");
        }

        let media_url = format!("{}{subdir}/{sha256_hex}{ext}", config.media_server_url);

        sqlx::query!(
            r#"
            INSERT INTO media_storage (media_url, storage_provider, added_at, key, h, ext, content_type, size, sha256, media_block_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) ON CONFLICT (h, storage_provider) DO UPDATE
            SET media_url = $1, added_at = $3, key = $4, ext = $6, content_type = $7, size = $8, sha256 = $9, media_block_id = $10
            "#,
            media_url,
            host,
            t,
            key.to_string(),
            h,
            ext,
            content_type,
            size,
            &sha256,
            None::<sqlx::types::Uuid>,
        ).execute(&state.cache_pool).await.map_log_err("db error".to_string())?;
    }

    sqlx::query!(
        r#"INSERT INTO media_uploads VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)"#,
        &e.pubkey.to_bytes(),
        "member_upload",
        key,
        t,
        // media_url,
        format!("{subdir}/{sha256_hex}{ext}"),
        size,
        content_type,
        "",
        1.0,
        0,
        0,
        0.0,
        &sha256,
        None::<String>,
        None::<sqlx::types::Uuid>, // media_block_id
    ).execute(&state.membership_pool).await.map_log_err("db error".to_string())?;

    state.cache.remove(&sha256);

    let blossom_url = format!("{}/{}{}", config.base_url, sha256_hex, ext);

    Ok((
        json!({
            "url": blossom_url,
            "sha256": sha256_hex,
            "size": size,
            "type": content_type,
            "uploaded": t,
        }),
        blossom_url,
    ))
}

#[derive(Debug,Clone)]
pub struct Upload {
    pub sha256:    Vec<u8>,
    pub media_url: String,
    pub mimetype:  String,
    pub size:      i64,
}

pub async fn find_blob(
    state: &State,
    sha256: Vec<u8>,
) -> Result<Option<Upload>, (StatusCode, String)> {
    if let Some(entry) = state.cache.get(&sha256) {
        // log!("cache hit for {sha256}");
        return Ok(entry.clone());
    }
    // log!("cache miss for {sha256}");

    let r = sqlx::query!(
        r#"
        SELECT ms.sha256,
               ms.media_url,
               ms.content_type AS mimetype,
               ms.size
          FROM media_storage ms
          JOIN media_storage_priority msp
            ON msp.storage_provider = ms.storage_provider
         WHERE ms.sha256 = $1
           AND ms.media_block_id IS NULL
         ORDER BY msp.priority
         LIMIT 1
        "#,
        sha256,
    ).fetch_optional(&state.cache_pool).await.map_log_err((StatusCode::INTERNAL_SERVER_ERROR, "db error".to_string()))?;

    let result = match r {
        Some(r) => match r.sha256 {
            Some(sha256) => Some(Upload {
                sha256,
                media_url: r.media_url,
                mimetype: r.mimetype,
                size: r.size,
            }),
            None => {
                log!("error: sha256 is None");
                None
            },
        },
        None => None,
    };

    state.cache.insert(sha256, result.clone());

    Ok(result)
}

// ------------------ media ---------------------

pub use tokio::process::Command;
pub use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
pub use std::process::Stdio;

pub use std::collections::HashMap;

pub use once_cell::sync::Lazy;
pub use tokio::fs;

pub use std::io::Write;

pub use std::ffi::OsString;

// TODO move to db
static MIMETYPE_EXT: Lazy<HashMap<&str, &str>> = Lazy::new(|| {
    [
        ("image/jpeg", ".jpg"),
        ("image/png", ".png"),
        ("image/gif", ".gif"),
        ("image/webp", ".webp"),
        ("image/svg+xml", ".svg"),
        ("video/mp4", ".mp4"),
        ("video/x-m4v", ".mp4"),
        ("video/mov", ".mov"),
        ("video/webp", ".webp"),
        ("video/webm", ".webm"),
        ("video/quicktime", ".mov"),
        ("video/x-matroska", ".mkv"),
        ("image/vnd.microsoft.icon", ".ico"),
        ("text/plain", ".txt"),
        ("application/json", ".json"),
        ("text/html", ".html"),
        ("text/javascript", ".js"),
        ("application/wasm", ".wasm"),
    ].iter().cloned().collect()
});

pub async fn parse_mimetype(data: &Vec<u8>) -> tokio::io::Result<String> {
    use tempfile::tempdir;
    let dir = tempdir()?;
    let path = dir.path().join("mimefile-parsing");

    use tokio::fs::OpenOptions;
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .await?;

    f.write_all(data).await?;
    f.flush().await?;

    let p = path.to_string_lossy().into_owned();

    let output = Command::new("file")
        .arg("-b")
        .arg("--mime-type")
        .arg(&p)
        .output()
        .await?;

    let mime_type = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(mime_type)
}

pub async fn execute_process(sandboxing: bool, state: &State, program_path: &OsString, args: &[&str], data: &[u8]) -> io::Result<Vec<u8>> {
    let mut cmd = if sandboxing {
        let mut cmd = Command::new("bwrap");
        cmd
            .arg("--new-session")
            .arg("--die-with-parent")
            .arg("--unshare-net")
            .arg("--ro-bind").arg("/nix").arg("/nix")
            .arg(program_path);
        cmd
    } else {
        Command::new(program_path)
    };

    cmd.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    let mut child = cmd.spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(data).await?;
    }

    let output = child.wait_with_output().await?;
    // dbg!(&cmd, program_path, output.status);
    Ok(output.stdout)
}

pub async fn strip_metadata(config: &Config, state: &State, data: Vec<u8>) -> io::Result<Vec<u8>> {
    match execute_process(config.sandboxing, state, &state.exiftool_path, &["-ignoreMinorErrors", "-all=", "-tagsfromfile", "@", "-Orientation", "-"], &data).await {
        Ok(output) => Ok(output),
        Err(_) => {
            let mime_type = parse_mimetype(&data).await?;
            if let Some(ext) = MIMETYPE_EXT.get(&mime_type.as_str()) {
                let ext = ext.replace(&".", &"");
                execute_process(config.sandboxing, state, &state.ffmpeg_path, &["-y", "-i", "-", "-map_metadata", "-1", "-c:v", "copy", "-c:a", "copy", "-f", &ext, "-"], &data).await
            } else {
                Err(io::Error::new(io::ErrorKind::Other, "unsupported mime type"))
            }
        }
    }
}

pub use reqwest::Client;
pub use std::time::Duration;

pub async fn download(url: &str, config: &Config) -> Result<Vec<u8>, reqwest::Error> {
    download_with_timeout(url, config, 300).await
}

pub async fn download_with_timeout(url: &str, config: &Config, timeout: u64) -> Result<Vec<u8>, reqwest::Error> {
    let mut client = Client::builder()
        .timeout(Duration::from_secs(timeout));

    if let Some(proxy) = &config.proxy {
        client = client.proxy(reqwest::Proxy::all(proxy)?);
    }

    let client = client.build()?;

    let response = client.get(url).send().await?;
    let data = response.bytes().await?.to_vec();
    Ok(data)
}

pub async fn file_exists_at_url_with_timeout(url: &str, config: &Config, timeout: u64) -> Result<bool, reqwest::Error> {
    let mut client = Client::builder()
        .timeout(Duration::from_secs(timeout));

    if let Some(proxy) = &config.proxy {
        client = client.proxy(reqwest::Proxy::all(proxy)?);
    }

    let client = client.build()?;

    let response = client.head(url).send().await?;
    Ok(response.status().is_success())
}

pub use sqlx::types::time::{OffsetDateTime, PrimitiveDateTime};

pub fn now_primitive() -> PrimitiveDateTime {
    let now = OffsetDateTime::now_utc();
    PrimitiveDateTime::new(now.date(), now.time())
}

pub async fn cache_data(
    config: &Config,
    data: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let sha256 = sha2::Sha256::digest(&data).to_vec();
    let sha256_hex = hex::encode(&sha256);
    let dir = format!(
        "{}/{}/{}",
        config.binary_data_cache_dir,
        &sha256_hex[0..2],
        &sha256_hex[2..4],
    );

    if !std::path::Path::new(dir.as_str()).exists() {
        tokio::fs::create_dir_all(&dir).await.map_log_err("create_dir_all failed".to_string())?;
    }

    let path = format!("{}/{}", dir, sha256_hex);
    if !std::path::Path::new(path.as_str()).exists() {
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .await
            .map_log_err("file creating failed".to_string())?;
        file.write_all(&data).await.map_log_err("file writing failed".to_string())?;
    }

    Ok(sha256)
}

#[cfg(feature = "media-processing")]
pub async fn schedule_processing_node(
    state: &State,
    module: &str,
    func: &str,
    args: Value,
    kwargs: Value,
) -> Result<Vec<u8>, String> {
    let id_str = json!({"mod": module, "func": func, "args": args, "kwargs": kwargs}).to_string();
    dbg!(&id_str);
    let id_data = id_str.as_bytes().to_vec();
    let id = sha2::Sha256::digest(&id_data).to_vec();

    sqlx::query!(
        r#"
        INSERT INTO processing_nodes (id, created_at, updated_at, mod, func, args, kwargs, exception)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (id) DO UPDATE SET started_at = null, finished_at = null
        "#,
        id,
        now_primitive(),
        now_primitive(),
        module,
        func,
        args,
        kwargs,
        false,
    )
    .execute(&state.cache_pool)
    .await.map_log_err("db error".to_string())?;

    Ok(id)
}

#[cfg(feature = "media-processing")]
pub async fn schedule_media_processing(
    config: &Config, state: &State,
    pubkey: PublicKey,
    data: Vec<u8>,
    sha256_before: Vec<u8>,
    blossom_url: String,
) -> Result<Vec<u8>, String> {
    schedule_processing_node(
        state, 
        "PrimalServer.App", 
        "import_upload_3",
        json!({
            "_ty": "Tuple",
            "_v": [
                {"_ty": "CacheStorage", "_v": Value::Null},
                {"_ty": "PubKeyId", "_v": pubkey.to_hex()},
                {"_ty": "Vector{UInt8}", "_cache_sha256": hex::encode(&cache_data(config, data).await?)},
                {"_ty": "Vector{UInt8}", "_v": hex::encode(&sha256_before)},
                blossom_url,
            ],
        }), 
        json!({ }),
    ).await
}

#[cfg(feature = "media-processing")]
pub async fn wait_processing_node(
    state: &State,
    node_id: Vec<u8>,
) -> Result<Value, String> {
    let mut count = 0;
    let delay_ms = 200;
    let timeout_secs = 120;
    let max_count = timeout_secs*1000/delay_ms;
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        count += 1;
        log!("wait_processing_node {}: {count}/{max_count}", hex::encode(&node_id));
        if count > max_count {
            break;
        }
        let r = sqlx::query!(
            r#"
            SELECT result, exception
              FROM processing_nodes
             WHERE id = $1
               AND finished_at IS NOT NULL
            "#,
            node_id,
        )
        .fetch_optional(&state.cache_pool)
        .await.map_log_err("db error".to_string())?;
        // log!("wait_processing_node {}: {:?}", hex::encode(&node_id), r);
        if let Some(r) = r {
            if r.exception {
                return Err(format!("processing node {} failed: {:?}", hex::encode(&node_id), r.result).to_string());
            } else {
                return Ok(match r.result {
                    None => Value::Null,
                    Some(result) => result,
                });
            }
        }
    }
    Err(format!("processing node {} timed out", hex::encode(node_id)).to_string())
}

