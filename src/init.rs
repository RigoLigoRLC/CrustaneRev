
use std::fs;
use std::os::unix::fs::PermissionsExt;
use tracing::info;
use crate::backend;
use crate::backend::backend::Backend;

fn ensure_dir_ok(path: &std::path::Path) -> Result<(), String> {
    let path_str = path.to_str().unwrap();

    if !match fs::exists(path) {
        Ok(exist) => exist,
        Err(error) => {
            return Err(format!("检查目录是否存在出错：{}\n目录：{}", error, path_str));
        }
    }{
        let create_result = fs::create_dir_all(path);
        if create_result.is_err() {
            return Err(format!("创建目录出错：{}\n目录：{}", create_result.unwrap_err(), path_str));
        }
    }

    let meta = match fs::metadata(path) {
        Ok(meta) => meta,
        Err(error) => {
            return Err(format!("获取目录信息出错：{}\n目录：{}", error, path_str));
        }
    };

    if !meta.is_dir() {
        return Err(format!("指定的目录不是目录\n目录：{}", path_str));
    }

    if meta.permissions().mode() & 0o700 != 0o700 {
        return Err(format!("指定的目录没有RWX权限\n目录：{}，mode为{:03o}", path_str, meta.permissions().mode()))
    }

    Ok(())
}

pub(crate) async fn initialize_backend() -> Result<Backend, String> {
    let data_dir = match std::env::var("CRUSTANEREV_DATA_DIR") {
        Ok(data_dir) => data_dir,
        Err(error) => {
            return Err(format!("获取CRUSTANEREV_DATA_DIR环境出错：{}", error));
        }
    };

    let base_path = std::path::Path::new(&data_dir);
    ensure_dir_ok(base_path)?;

    // ./active_profile
    let active_profile_path = base_path.join("active_profile");
    ensure_dir_ok(active_profile_path.as_path())?;

    // ./active_profile/sticker_store
    ensure_dir_ok(active_profile_path.join("sticker_store").as_path())?;

    // ./backups
    ensure_dir_ok(base_path.join("backups").as_path())?;

    // ./ota
    ensure_dir_ok(base_path.join("ota").as_path())?;

    // SQLite database
    let backend = Backend::new(&active_profile_path).await?;

    info!("后端初始化完成，当前活动Profile：{}", active_profile_path.display());

    Ok(backend)
}
