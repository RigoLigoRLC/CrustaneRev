use sqlx::{query, query_as};
use tracing::info;
use crate::backend::backend::DbMetaResult;
use crate::error_glue::CrustaneError;

const CURRENT_DB_VERSION: i64 = 3;

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
            domain_openid TEXT,
            view_level INTEGER NOT NULL,
            uploader_openid TEXT NOT NULL
        );
        -- Deleted stickers table
        CREATE TABLE IF NOT EXISTS stickers_deleted (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            tags TEXT NOT NULL,
            added_date TEXT NOT NULL,
            domain_openid TEXT,
            view_level INTEGER NOT NULL,
            uploader_openid TEXT NOT NULL
        );

        -- Stickers search table
        CREATE VIRTUAL TABLE IF NOT EXISTS stickers_search USING fts5(
            tags,
            content='stickers',
            content_rowid='id',
            tokenize='simple'
        );

        -- Sticker liberators
        CREATE TABLE IF NOT EXISTS sticker_liberators (
            openid TEXT PRIMARY KEY NOT NULL
        );

        -- Tencent cache layer (L1)
        CREATE TABLE IF NOT EXISTS sticker_cache_tencent (
            id INTEGER PRIMARY KEY,
            media TEXT NOT NULL,
            expiration_timestamp INTEGER NOT NULL,
            chat_type INTEGER NOT NULL
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

async fn database_meta(pool: &sqlx::SqlitePool, key: &str) -> Result<Option<String>, sqlx::Error> {
    match query_as::<_, DbMetaResult>("SELECT value FROM crustanerev_meta WHERE key=?")
        .bind(key)
        .fetch_all(pool)
        .await
    {
        Ok(x) => Ok(x.into_iter().next().map(|x| x.value)),
        Err(e) => Err(e),
    }
}

async fn database_version(pool: &sqlx::SqlitePool) -> Result<i64, CrustaneError> {
    let str_val = match database_meta(pool, "VERSION").await {
        Ok(x) => {
            if let Some(x) = x {
                x
            } else {
                return Err("严重错误：数据库非空，但crustanerev_meta表中没有VERSION键！".into());
            }
        }
        Err(e) => return Err(format!("查询数据库元数据VERSION时出错：{}", e).into()),
    };
    match str_val.parse::<i64>() {
        Ok(x) => Ok(x),
        Err(e) => Err(format!("数据库元数据VERSION（{}）不是有效的i64：{}", str_val, e).into()),
    }
}

async fn database_upgraded_to(
    pool: &sqlx::SqlitePool,
    new_version: i64,
) -> Result<i64, CrustaneError> {
    match query("UPDATE crustanerev_meta SET value=? WHERE key=?")
        .bind(new_version.to_string())
        .bind("VERSION")
        .fetch_all(pool)
        .await
    {
        Ok(_) => Ok(new_version),
        Err(e) => Err(format!("无法将数据库版本翻到{}：{}", new_version, e).into()),
    }
}

pub async fn database_migration_or_initialization(
    pool: &sqlx::SqlitePool,
) -> Result<(), CrustaneError> {
    let meta_table =
        query("SELECT name FROM sqlite_master WHERE type='table' AND name='crustanerev_meta'")
            .fetch_all(pool)
            .await?;

    if meta_table.is_empty() {
        info!("数据库中没有任何表，将创建新的表结构");
        create_initial_tables(pool).await?;
    } else {
        let mut version: i64 = database_version(pool).await?;
        if version == CURRENT_DB_VERSION {
            return Ok(());
        }

        if version == 1 {
            // V1 -> V2: view_level=1 应全变为 view_level=100
            query("UPDATE stickers SET view_level=100 WHERE view_level=1")
                .fetch_all(pool)
                .await?;
            version = database_upgraded_to(pool, 2).await?;
        }

        if version == 2 {
            // V2 -> V3: 创建虚拟删除表
            query(
            "CREATE TABLE IF NOT EXISTS stickers_deleted (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filename TEXT NOT NULL,
                    tags TEXT NOT NULL,
                    added_date TEXT NOT NULL,
                    domain_openid TEXT,
                    view_level INTEGER NOT NULL,
                    uploader_openid TEXT NOT NULL
                );")
            .fetch_all(pool)
            .await?;
            version = database_upgraded_to(pool, 3).await?;
        }

        info!("数据库已升级到版本{}。", version);
    }

    Ok(())
}