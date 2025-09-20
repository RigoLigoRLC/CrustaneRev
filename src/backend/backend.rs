use std::path::PathBuf;
use sqlx::migrate::MigrateDatabase;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::{query, Column, Row};
use tokio::fs::File;
use tracing::{error, info};
use crate::utils;

pub struct Backend {
    profile_path: PathBuf,
    db: sqlx::SqlitePool,

    sticker_store_path: PathBuf,
}

pub enum StickerUploadDomain {
    User,
    Group
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
    pub async fn new(profile_path: &PathBuf) -> Result<Backend, String> {
        let db_path = format!("sqlite:{}/database.db", profile_path.to_str().unwrap());
        info!("数据库路径: {}", db_path);

        if !profile_path.join("database.db").exists() {
            match sqlx::sqlite::Sqlite::create_database(db_path.as_str()).await {
                Ok(_) => (),
                Err(e) => {
                    return Err(format!("创建数据库失败：{}", e.to_string()));
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
            Err(e) => { return Err(format!("打开数据库失败：{}", e)); },
        };

        // If database has just been created or needs migration, do them here
        match database_migration_or_initialization(&db).await {
            Ok(_) => (),
            Err(e) => {
                let err = e.to_string();
                error!("数据库初始化/迁移失败：{}", err);
                return Err(err);
            },
        }

        Ok(Backend {
            profile_path: profile_path.clone(),
            sticker_store_path: profile_path.join("sticker_store"),
            db
        })
    }

    pub async fn handle_sticker_upload(
        &self,
        url: &String,
        file_name: String,
        domain_openid: &String,
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
}
