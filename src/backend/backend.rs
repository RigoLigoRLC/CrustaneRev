use std::ops::Deref;
use std::path::PathBuf;
use std::sync::LazyLock;
use aws_config::{defaults, BehaviorVersion};
use aws_sdk_s3::primitives::ByteStream;
use botrs::{Context, Media};
use chrono::{Utc, DateTime, FixedOffset, TimeZone};
use regex::Regex;
use sqlx::migrate::MigrateDatabase;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::{query, query_as, Column, FromRow, Row};
use tokio::fs::File;
use tracing::{debug, error, info};
use uuid::Uuid;
use crate::error_glue::CrustaneError;
use crate::utils;

const BUCKET_NAME: &str = "crustanerev-sticker-upload";

pub struct Backend {
    profile_path: PathBuf,
    sticker_store_path: PathBuf,
    s3_bucket_prefix: String,

    db: sqlx::SqlitePool,
    s3: aws_sdk_s3::Client,
}

/// Which domain does this sticker belongs to, inside CrustaneRev
pub enum StickerDomain {
    User,
    Group
}

/// Where are you sending this sticker to
pub enum StickerRecipient {
    User,
    Group,
}

#[derive(Debug, FromRow)]
pub struct StickerQueryResultSimple {
    pub(crate) id: i64,
    pub(crate) filename: String,
    pub(crate) tags: String,
}

#[derive(Debug, FromRow)]
pub struct StickerIdQueryDomainlessResult {
    pub(crate) id: i64,
}

#[derive(Debug, FromRow)]
struct StickerCacheS3QueryResult {
    pub s3_key: String,
    pub expiration_timestamp: i64,
}

#[derive(Debug, FromRow)]
struct StickerCacheTencentQueryResult {
    pub url: String,
    pub expiration_timestamp: i64,
}

fn expiry_date_parse(expiration_str: String) -> i64 {
    static EXPIRY_DATE_RE: LazyLock<Regex, fn() -> Regex> = LazyLock::new(|| Regex::new(r#"expiry-date="(.+?)""#).unwrap());
    debug!("Parsing expiration date: {}", expiration_str);
    EXPIRY_DATE_RE.find(expiration_str.as_ref()).map_or(
        Utc::now().timestamp(),
        |s| DateTime::parse_from_str(
            expiration_str.as_ref(), "%a, %m %b %Y %H:%M:%S %Z"
        ).unwrap_or(Utc::now().into()).timestamp()
    )
}

async fn create_initial_tables(pool: &sqlx::SqlitePool) -> Result<(), sqlx::Error> {
    query(
        "BEGIN;

        -- Metadata
        CREATE TABLE crustanerev_meta (
            key TEXT NOT NULL PRIMARY KEY,
            value TEXT
        );

        INSERT INTO crustanerev_meta (key, value) VALUES
            ('VERSION', '1')
        ;

        -- Stickers table
        CREATE TABLE IF NOT EXISTS stickers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            tags TEXT NOT NULL,
            added_date TEXT NOT NULL,
            domain_openid TEXT
        );

        -- Stickers search table
        CREATE VIRTUAL TABLE IF NOT EXISTS stickers_search USING fts5(
            tags,
            content='stickers',
            content_rowid='id',
            tokenize='simple'
        );

        -- Tencent cache layer (L1)
        CREATE TABLE IF NOT EXISTS sticker_cache_tencent_group (
            id INTEGER PRIMARY KEY,
            url TEXT NOT NULL,
            expiration_timestamp INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sticker_cache_tencent_user (
            id INTEGER PRIMARY KEY,
            url TEXT NOT NULL,
            expiration_timestamp INTEGER NOT NULL
        );

        -- S3 cache layer (L2)
        CREATE TABLE IF NOT EXISTS sticker_cache_s3 (
            id INTEGER PRIMARY KEY,
            s3_key TEXT NOT NULL,
            expiration_timestamp INTEGER NOT NULL
        );

        -- On insert: add to index
        CREATE TRIGGER stickers_ai AFTER INSERT ON stickers BEGIN
          INSERT INTO stickers_search(rowid, tags) VALUES (new.id, new.tags);
        END;

        -- On delete: remove from index
        CREATE TRIGGER stickers_ad AFTER DELETE ON stickers BEGIN
          INSERT INTO stickers_search(stickers_search, rowid, tags)
            VALUES('delete', old.id, old.tags);
        END;

        -- On update: update index
        CREATE TRIGGER stickers_au AFTER UPDATE ON stickers BEGIN
          INSERT INTO stickers_search(stickers_search, rowid, tags) VALUES('delete', old.id, old.tags);
          INSERT INTO stickers_search(rowid, tags) VALUES (new.id, new.tags);
        END;

        END;
        "
    ).fetch_all(pool).await?;

    Ok(())
}

async fn database_migration_or_initialization(pool: &sqlx::SqlitePool) -> Result<(), sqlx::Error> {
    let meta_table =
        query("SELECT name FROM sqlite_master WHERE type='table' AND name='crustanerev_meta'")
            .fetch_all(pool)
            .await?;

    if meta_table.is_empty() {
        info!("数据库中没有任何表，将创建新的表结构");
        create_initial_tables(pool).await?;
    } else {

    }

    Ok(())
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
            .connect(db_path.as_str()).await;

        let db = match db {
            Ok(db) => db,
            Err(e) => { return Err(format!("打开数据库失败：{}", e).into()); },
        };

        // If database has just been created or needs migration, do them here
        match database_migration_or_initialization(&db).await {
            Ok(_) => (),
            Err(e) => {
                let err = e.to_string();
                error!("数据库初始化/迁移失败：{}", err);
                return Err(err.into());
            },
        }

        // Initialize S3
        let s3_config = aws_config::defaults(BehaviorVersion::latest())
            .endpoint_url(std::env::var("CRUSTANEREV_S3_ENDPOINT_URL")?)
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                std::env::var("CRUSTANEREV_S3_ACCESS_KEY")?,
                std::env::var("CRUSTANEREV_S3_SECRET_KEY")?,
                None,
                None,
                "R2"
            ))
            .region("auto")
            .load()
            .await;

        let s3 = aws_sdk_s3::Client::new(&s3_config);
        let s3_bucket_prefix = std::env::var("CRUSTANEREV_S3_BUCKET_PREFIX")?;

        Ok(Backend {
            profile_path: profile_path.clone(),
            sticker_store_path: profile_path.join("sticker_store"),
            s3_bucket_prefix,
            db,
            s3,
        })
    }

    pub async fn handle_sticker_upload(
        &self,
        url: &String,
        file_name: String,
        domain_openid: &str,
        tags: String,
    ) -> Result<(), String> {
        let output_path = self.sticker_store_path.join(&file_name);
        utils::download_file(url, output_path.to_str().unwrap()).await?;

        match query(
            "INSERT INTO stickers (filename, tags, added_date, domain_openid)
             VALUES (?, ?, datetime('now', 'localtime'), ?)")
            .bind(file_name)
            .bind(tags)
            .bind(domain_openid)
            .fetch_all(&self.db).await {

            Ok(_) => Ok(()),
            Err(e) => {
                let rm_msg = match tokio::fs::remove_file(output_path).await {
                    Ok(_) => "".into(),
                    Err(e) => format!("\n已下载的文件未能成功删除：{}", e)
                };
                Err(format!("数据库操作出错：{}{}", e, rm_msg))
            }
        }
    }

    pub async fn sticker_id_query_domainless(
        &self,
        keyword: String
    ) -> Result<Vec<i64>, String> {
        match query_as::<_, StickerIdQueryDomainlessResult>("
            SELECT s.id
            FROM stickers s
            JOIN stickers_search ss ON s.id=ss.rowid
            WHERE stickers_search MATCH simple_query(?)
        ")
            .bind(keyword)
            .fetch_all(&self.db).await {
            Ok(result) => Ok(result.iter().map(|it| it.id).collect()),
            Err(e) => Err(format!("数据库操作出错：{}", e))
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
            WHERE stickers_search MATCH simple_query(?)
            LIMIT 20
        "
        ).bind(keyword).bind(user_openid).bind(group_openid).fetch_all(&self.db).await {
            Ok(result) => Ok(result),
            Err(e) => Err(format!("数据库操作出错：{}", e))
        }
    }

    pub async fn sticker_upload_to_s3(
        &self,
        id: i64,
        filename: &String,
    ) -> Result<String, CrustaneError> {
        let mut result = query_as::<_, StickerCacheS3QueryResult>("
            SELECT s.s3_key, s.expiration_timestamp
            FROM sticker_cache_s3 s
            WHERE s.id=?
        ").bind(id).fetch_all(&self.db).await?;

        let key = if result.is_empty() {
            // Not cached
            let key = Uuid::new_v4().to_string();
            let body = ByteStream::from_path(self.sticker_store_path.join(filename)).await.unwrap();
            let put_result = match self.s3.put_object()
                .bucket(BUCKET_NAME)
                .key(key.as_str())
                .body(body)
                .send()
                .await {
                Ok(result) => result,
                Err(e) => return Err(format!("S3 Error: {}", e).into())
            };
            query("INSERT INTO sticker_cache_s3 (id, s3_key, expiration_timestamp) VALUES (?,?,?);")
                .bind(id)
                .bind(key.as_str())
                .bind(expiry_date_parse(put_result.expiration.unwrap_or(String::new())))
                .fetch_all(&self.db).await?;
            key
        } else {
            let result2 = result.remove(0);
            let key = result2.s3_key;
            if result2.expiration_timestamp + 300 > Utc::now().timestamp() {
                // Expiring in 300 seconds, copy the object
                let new_key = Uuid::new_v4().to_string();
                let copy_result = match self.s3.copy_object()
                    .bucket(BUCKET_NAME)
                    .copy_source(key)
                    .key(new_key.as_str())
                    .send()
                    .await {
                    Ok(result) => result,
                    Err(e) => return Err(format!("S3 Error: {}", e).into())
                };
                query("UPDATE sticker_cache_s3 SET s3_key=? WHERE id=?").bind(new_key.as_str()).bind(id).fetch_all(&self.db).await?;
                new_key
            } else {
                // Cache hit
                key
            }
        };

        Ok(format!("{}{}", self.s3_bucket_prefix, key))
    }

    pub async fn sticker_upload_to_tencent(
        &self,
        ctx: &Context,
        recipient: StickerRecipient,
        openid: &String,
        id: i64,
        filename: String,
    ) -> Result<String, CrustaneError> {
        let table = match recipient {
            StickerRecipient::User => "sticker_cache_tencent_user",
            StickerRecipient::Group => "sticker_cache_tencent_group",
        };
        let mut result = query_as::<_, StickerCacheTencentQueryResult>("
            SELECT s.url, s.expiration_timestamp
            FROM ? s
            WHERE s.id=?
        ").bind(table).bind(id).fetch_all(&self.db).await?;

        if result.is_empty() || result.first().unwrap().expiration_timestamp + 300 > Utc::now().timestamp() {
            // Have never been uploaded to Tencent at all, or Tencent cache will soon expire
            let s3_url = self.sticker_upload_to_s3(id, &filename).await?;

            serde_json::from_value::<botrs::models::message::Media>(match recipient {
                StickerRecipient::User => unimplemented!(),
                StickerRecipient::Group => {
                    ctx.api.post_group_file(
                        &ctx.token,
                        openid,
                        1, // image
                        s3_url.as_str(),
                        None
                    ).await?
                }
            })?;

            todo!()
        }
    }
}
