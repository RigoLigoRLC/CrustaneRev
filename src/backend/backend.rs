
use sqlx::migrate::MigrateDatabase;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::query;
use tracing::info;

pub struct Backend {
    db: sqlx::SqlitePool,
}

async fn create_initial_tables(pool: &sqlx::SqlitePool) -> Result<(), sqlx::Error> {
    query(
        "BEGIN;

        CREATE TABLE IF NOT EXISTS db (
            
        "
    ).fetch_all(pool).await?;

    Ok(())
}

async fn database_migration_or_initialization(pool: &sqlx::SqlitePool) -> Result<(), sqlx::Error> {
    let meta_table =
        query("SELECT name FROM sqlite_master WHERE type='table' AND name='CRUSTANEREV_META'")
            .fetch_all(pool)
            .await?;

    if meta_table.is_empty() {
        create_initial_tables(pool).await?;
    } else {

    }

    Ok(())
}

impl Backend {
    pub async fn new(profile_path: &std::path::PathBuf) -> Result<Backend, String> {
        let mut init_tables: bool = false;
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
            init_tables = true;
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
        database_migration_or_initialization(&db);

        Ok(Backend {
            db,
        })
    }
}
