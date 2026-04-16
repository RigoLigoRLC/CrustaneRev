use crate::error_glue::CrustaneError;
use crate::utils;
use aws_config::{defaults, BehaviorVersion};
use aws_sdk_s3::primitives::ByteStream;
use botrs::{Context, GroupMessage, Media};
use chrono::{DateTime, FixedOffset, ParseResult, TimeZone, Utc};
use regex::{Match, Regex};
use sqlx::migrate::MigrateDatabase;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::{query, query_as, Column, Execute, FromRow, Row};
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::{LazyLock, RwLock};
use tokio::fs::File;
use totp_rs::TOTP;
use tracing::{debug, error, info};
use uuid::Uuid;
use crate::backend::{dbmaint, superuser};
use crate::backend::superuser::SuperUserState;
use crate::utils::{get_sender_openid_group_msg, get_totp};
use crate::utils::wrappers::WrappedMessageType;

const BUCKET_NAME: &str = "crustanerev-sticker-upload";

pub struct Backend {
    // Vital address strings
    profile_path: PathBuf,
    sticker_store_path: PathBuf,
    s3_bucket_prefix: String,

    // For superuser verification
    superuser_state: SuperUserState,

    // Database and S3 connection
    db: sqlx::SqlitePool,
    s3: aws_sdk_s3::Client,
}

/// Which domain does this sticker belongs to, inside CrustaneRev
pub enum StickerDomain {
    User,
    Group,
}

/// Where are you sending this sticker to
pub enum StickerRecipient {
    User,
    Group,
}

/// Operations on Sticker liberators
pub enum StickerLiberatorOperation {
    Add,
    Verify,
    Remove,
}

#[derive(Debug, FromRow)]
pub struct DbMetaResult {
    pub(crate) value: String,
}

#[derive(Debug, FromRow)]
pub struct StickerQueryResultSimple {
    pub(crate) id: i64,
    pub(crate) filename: String,
    pub(crate) tags: String,
}

#[derive(Debug, FromRow)]
pub struct StickerIdQueryResult {
    pub(crate) id: i64,
}

#[derive(Debug, FromRow)]
pub struct StickerInspectSimpleResult {
    pub(crate) filename: String,
    pub(crate) tags: String,
    pub(crate) added_date: String,
    pub(crate) domain_openid: String,
    pub(crate) uploader_openid: String,
    pub(crate) view_level: i64,
}

#[derive(Debug, FromRow)]
pub struct StickerUploaderOpenIdQueryResult {
    pub(crate) uploader_openid: String,
}

#[derive(Debug, FromRow)]
struct StickerCacheS3QueryResult {
    pub s3_key: String,
    pub expiration_timestamp: i64,
}

#[derive(Debug, FromRow)]
struct StickerCacheTencentQueryResult {
    pub media: String,
    pub expiration_timestamp: i64,
}

fn expiry_date_parse(expiration_str: String) -> i64 {
    static EXPIRY_DATE_RE: LazyLock<Regex, fn() -> Regex> =
        LazyLock::new(|| Regex::new(r#"expiry-date="(.+?)""#).unwrap());
    debug!("Parsing expiration date: {}", expiration_str);
    match EXPIRY_DATE_RE.captures(expiration_str.as_ref()) {
        None => {
            error!("Expiration date not matched inside expiry date string, using current time");
            Utc::now().timestamp()
        }
        Some(cap) => match cap.get(1) {
            None => {
                error!("Cannot get 1st capture group, using current time");
                Utc::now().timestamp()
            }
            Some(s) => match DateTime::parse_from_rfc2822(s.as_str()) {
                Ok(time) => {
                    info!("Parsed time: {}", time.to_rfc2822());
                    time.timestamp()
                }
                Err(e) => {
                    error!("Failed to parse expiration date: {}, using current tme", e);
                    Utc::now().timestamp()
                }
            },
        },
    }
}

impl Backend {
    /// Returns Err(error_string) when initialization failed
    pub async fn new(profile_path: &PathBuf) -> Result<Backend, CrustaneError> {
        let db_path = format!("sqlite:{}/database.db", profile_path.to_str().unwrap());
        info!("数据库路径: {}", db_path);

        if !profile_path.join("database.db").exists() {
            match sqlx::sqlite::Sqlite::create_database(db_path.as_str()).await {
                Ok(_) => (),
                Err(e) => {
                    return Err(format!("创建数据库失败：{}", e.to_string()).into());
                }
            }

            info!("创建了数据库文件{}", db_path);
        }

        // Connect database
        let db = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(db_path.as_str())
            .await;

        let db = match db {
            Ok(db) => db,
            Err(e) => {
                return Err(format!("打开数据库失败：{}", e).into());
            }
        };

        // If database has just been created or needs migration, do them here
        match dbmaint::database_migration_or_initialization(&db).await {
            Ok(_) => (),
            Err(e) => {
                let err = e.to_string();
                error!("数据库初始化/迁移失败：{}", err);
                return Err(err.into());
            }
        }

        // Initialize S3
        let s3_config = aws_config::defaults(BehaviorVersion::latest())
            .endpoint_url(std::env::var("CRUSTANEREV_S3_ENDPOINT_URL")?)
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                std::env::var("CRUSTANEREV_S3_ACCESS_KEY")?,
                std::env::var("CRUSTANEREV_S3_SECRET_KEY")?,
                None,
                None,
                "R2",
            ))
            .region("auto")
            .load()
            .await;

        let s3 = aws_sdk_s3::Client::new(&s3_config);
        let s3_bucket_prefix = std::env::var("CRUSTANEREV_S3_BUCKET_PREFIX")?;

        // Initialize TOTP code generator for superuser verifier
        let totp_gen = get_totp()?;
        let superuser_state = SuperUserState::new(totp_gen);

        Ok(Backend {
            profile_path: profile_path.clone(),
            sticker_store_path: profile_path.join("sticker_store"),
            s3_bucket_prefix,
            superuser_state,
            db,
            s3,
        })
    }

    pub fn superuser_state(&self) -> &SuperUserState { &self.superuser_state }

    pub async fn handle_sticker_upload(
        &self,
        url: &String,
        file_name: String,
        domain_openid: &str,
        uploader_openid: &str,
        tags: String,
    ) -> Result<i64, String> {
        let output_path = self.sticker_store_path.join(&file_name);
        utils::download_file(url, output_path.to_str().unwrap()).await?;

        let view_level = match self
            .sticker_liberator_ops(domain_openid, StickerLiberatorOperation::Verify)
            .await
        {
            Ok(n) => {
                if n != 0 {
                    0
                } else {
                    100
                }
            }
            Err(e) => return Err(e.into()),
        };

        match query_as::<_, StickerIdQueryResult>("
            INSERT INTO stickers (filename, tags, added_date, domain_openid, view_level, uploader_openid)
             VALUES (?, ?, datetime('now', 'localtime'), ?, ?, ?)
             RETURNING id
        ")
            .bind(file_name)
            .bind(tags)
            .bind(domain_openid)
            .bind(view_level)
            .bind(uploader_openid)
            .fetch_all(&self.db).await {

            Ok(x) => Ok(x.into_iter().next().unwrap().id),
            Err(e) => {
                let rm_msg = match tokio::fs::remove_file(output_path).await {
                    Ok(_) => "".into(),
                    Err(e) => format!("\n已下载的文件未能成功删除：{}", e)
                };
                Err(format!("数据库操作出错：{}{}", e, rm_msg))
            }
        }
    }

    pub async fn sticker_query_simple(
        &self,
        keyword: String,
        user_openid: &str,
        group_openid: &str,
    ) -> Result<Vec<StickerQueryResultSimple>, String> {
        match query_as::<_, StickerQueryResultSimple>("
SELECT s.id, s.filename, s.tags
FROM stickers s
JOIN stickers_search ss ON s.id=ss.rowid
WHERE
    stickers_search MATCH simple_query(?) AND
    (s.domain_openid IN (?, ?) OR s.view_level = 0)
LIMIT 20")
            .bind(keyword)
            .bind(user_openid)
            .bind(group_openid)
            .fetch_all(&self.db).await {
                Ok(result) => Ok(result),
                Err(e) => Err(format!("数据库操作出错：{}", e)),
            }
    }

    pub async fn sticker_id_query_domainless(&self, keyword: String) -> Result<Vec<i64>, String> {
        match query_as::<_, StickerIdQueryResult>(
            "
            SELECT s.id
            FROM stickers s
            JOIN stickers_search ss ON s.id=ss.rowid
            WHERE stickers_search MATCH simple_query(?)
        ",
        )
        .bind(keyword)
        .fetch_all(&self.db)
        .await
        {
            Ok(result) => Ok(result.iter().map(|it| it.id).collect()),
            Err(e) => Err(format!("数据库操作出错：{}", e)),
        }
    }

    pub async fn sticker_uploader_openid_query(&self, id: i64) -> Result<String, String> {
        let sticker_uploader_openid = match query_as::<_, StickerUploaderOpenIdQueryResult>(
            "SELECT s.uploader_openid FROM stickers s WHERE id=?",
        )
        .bind(id)
        .fetch_all(&self.db)
        .await
        {
            Ok(x) => {
                if x.is_empty() {
                    return Err(format!("找不到ID={}的表情包。", id));
                }
                x.into_iter().next().unwrap().uploader_openid
            }
            Err(e) => return Err(format!("数据库操作出错：{}", e)),
        };
        Ok(sticker_uploader_openid)
    }

    pub async fn sticker_inspect_simple(
        &self,
        id: i64,
    ) -> Result<Option<StickerInspectSimpleResult>, CrustaneError> {
        match query_as::<_, StickerInspectSimpleResult>("
            SELECT s.filename, s.tags, s.added_date, s.domain_openid, s.view_level, s.uploader_openid
            FROM stickers s
            WHERE s.id=?
        ").bind(id).fetch_optional(&self.db).await {
            Ok(result) => Ok(result),
            Err(e) => Err(format!("数据库操作出错：{}", e).into())
        }
    }

    pub async fn sticker_exists(&self, id: i64) -> Result<bool, String> {
        match query("SELECT s.id FROM stickers s WHERE id=?")
            .bind(id)
            .fetch_all(&self.db)
            .await
        {
            Ok(result) => Ok(result.len() != 0),
            Err(e) => Err(format!("数据库操作出错：{}", e)),
        }
    }

    pub async fn sticker_liberate_all(&self, openid: &str) -> Result<i64, String> {
        match query("UPDATE stickers SET view_level=0 WHERE uploader_openid=?")
            .bind(openid)
            .fetch_all(&self.db)
            .await
        {
            Ok(result) => Ok(result.len() as i64),
            Err(e) => Err(format!("数据库操作出错：{}", e)),
        }
    }

    pub async fn sticker_liberate_one(
        &self,
        is_superuser: bool,
        openid: &str,
        id: i64,
    ) -> Result<(), String> {
        if is_superuser {
            match query("UPDATE stickers SET view_level=0 WHERE id=?")
                .bind(id)
                .fetch_all(&self.db)
                .await
            {
                Ok(_) => Ok(()),
                Err(e) => Err(format!("数据库操作出错：{}", e)),
            }
        } else {
            let sticker_uploader_openid = match self.sticker_uploader_openid_query(id).await {
                Ok(value) => value,
                Err(value) => value,
            };

            if sticker_uploader_openid != openid {
                return Err("抱歉，您不是超级用户，不能操作其他人上传的表情包。".into());
            }

            match query("UPDATE stickers SET view_level=0 WHERE uploader_openid=? AND id=?")
                .bind(openid)
                .bind(id)
                .fetch_all(&self.db)
                .await
            {
                Ok(_) => Ok(()),
                Err(e) => Err(format!("数据库操作出错：{}", e)),
            }
        }
    }

    pub async fn sticker_set_tags(&self, id: i64, tags: &str) -> Result<(), CrustaneError> {
        match query("UPDATE stickers SET tags=? WHERE id=?")
            .bind(tags)
            .bind(id)
            .fetch_all(&self.db)
            .await
        {
            Ok(x) => Ok(()),
            Err(e) => Err(format!("数据库操作出错：{}", e).into()),
        }
    }

    pub async fn sticker_upload_to_s3(
        &self,
        id: i64,
        filename: &String,
    ) -> Result<String, CrustaneError> {
        let mut result = query_as::<_, StickerCacheS3QueryResult>(
            "
            SELECT s.s3_key, s.expiration_timestamp
            FROM sticker_cache_s3 s
            WHERE s.id=?
        ",
        )
        .bind(id)
        .fetch_all(&self.db)
        .await?;

        let first_result = result.into_iter().next().map_or(None, |x| Some(x));
        let key = if first_result.is_none()
            || Utc::now().timestamp() + 300 > first_result.as_ref().unwrap().expiration_timestamp
        {
            // Not cached or expiring in 300 seconds
            let key = Uuid::new_v4().to_string();
            let body = ByteStream::from_path(self.sticker_store_path.join(filename))
                .await
                .unwrap();
            let put_result = match self
                .s3
                .put_object()
                .bucket(BUCKET_NAME)
                .key(key.as_str())
                .body(body)
                .send()
                .await
            {
                Ok(result) => result,
                Err(e) => return Err(format!("S3 Error: {}", e).into()),
            };
            query(
                "
                INSERT INTO sticker_cache_s3 (id, s3_key, expiration_timestamp)
                VALUES (?,?,?)
                ON CONFLICT (id) DO UPDATE SET
                    s3_key = excluded.s3_key,
                    expiration_timestamp = excluded.expiration_timestamp;
            ",
            )
            .bind(id)
            .bind(key.as_str())
            .bind(expiry_date_parse(
                put_result.expiration.unwrap_or(String::new()),
            ))
            .fetch_all(&self.db)
            .await?;
            key
        } else {
            // Cache hit
            first_result.unwrap().s3_key
        };

        Ok(format!("{}{}", self.s3_bucket_prefix, key))
    }

    pub async fn sticker_upload_to_tencent(
        &self,
        ctx: &Context,
        recipient_type: WrappedMessageType,
        openid: &str,
        id: i64,
        filename: String,
    ) -> Result<Media, CrustaneError> {
        let chat_type = match recipient_type {
            WrappedMessageType::C2CMessage => 0,
            WrappedMessageType::GroupMessage => 1,
        };

        let result = query_as::<_, StickerCacheTencentQueryResult>(
            "SELECT s.media, s.expiration_timestamp FROM sticker_cache_tencent s WHERE s.id=? AND s.chat_type=?"
        ).bind(id).bind(chat_type).fetch_all(&self.db).await?;

        let first_result = result.first();
        if result.is_empty()
            || Utc::now().timestamp() + 300 > first_result.unwrap().expiration_timestamp
        {
            // Have never been uploaded to Tencent at all, or Tencent cache will soon expire
            let s3_url = self.sticker_upload_to_s3(id, &filename).await?;

            // Try upload to Tencent
            let result = match recipient_type {
                WrappedMessageType::C2CMessage => {
                    ctx.api
                        .post_c2c_file(
                            &ctx.token,
                            openid,
                            1, // image,
                            s3_url.as_str(),
                            None,
                        )
                        .await?
                }
                WrappedMessageType::GroupMessage => {
                    ctx.api
                        .post_group_file(
                            &ctx.token,
                            openid,
                            1, // image
                            s3_url.as_str(),
                            None,
                        )
                        .await?
                }
            };
            let result_str = format!("{}", result);
            let media = match serde_json::from_value::<Media>(result) {
                Ok(media) => media,
                Err(e) => {
                    error!("Uploading to Tencent failed: {}", result_str);
                    return Err(format!(
                        "Error when serde_json::from_value::<Media> from request result: {}",
                        e
                    )
                    .into());
                }
            };

            // Insert to database
            let _ = query(
                "
                INSERT INTO sticker_cache_tencent (id, media, expiration_timestamp, chat_type)
                VALUES (?, ?, ?, ?)
                ON CONFLICT (id) DO UPDATE SET
                    media = excluded.media,
                    expiration_timestamp = excluded.expiration_timestamp
            ",
            )
            .bind(id)
            .bind(result_str)
            .bind(Utc::now().timestamp() + media.ttl.unwrap_or(86400) as i64)
            .bind(chat_type)
            .fetch_all(&self.db)
            .await?;

            Ok(media)
        } else {
            let media_str = &first_result.unwrap().media;
            match serde_json::from_str::<Media>(media_str.as_ref()) {
                Ok(media) => Ok(media),
                Err(e) => {
                    error!(
                        "Invalid JSON entry in Tencent cache layer, id={}, json={}",
                        id, media_str
                    );
                    // 删除掉有问题的项
                    query("DELETE FROM sticker_cache_tencent where id=?")
                        .bind(id)
                        .fetch_all(&self.db)
                        .await?;
                    Err(e.into())
                }
            }
        }
    }

    pub async fn sticker_liberator_ops(
        &self,
        openid: &str,
        operation: StickerLiberatorOperation,
    ) -> Result<i32, CrustaneError> {
        match match operation {
            StickerLiberatorOperation::Add => {
                query("INSERT INTO sticker_liberators (openid) VALUES (?);").bind(openid)
            }
            StickerLiberatorOperation::Remove => {
                query("DELETE FROM sticker_liberators WHERE openid=?;").bind(openid)
            }
            StickerLiberatorOperation::Verify => {
                query("SELECT * FROM sticker_liberators WHERE openid=?").bind(openid)
            }
        }
        .fetch_all(&self.db)
        .await
        {
            Ok(result) => Ok(result.len() as i32),
            Err(e) => Err(e.into()),
        }
    }
}
