use std::sync::RwLock;
use chrono::{DateTime, Utc};
use botrs::GroupMessage;
use totp_rs::TOTP;
use crate::utils::{get_sender_openid_group_msg, get_totp};

pub struct SuperUserState {
    totp_gen: TOTP,
    last_totp_code: RwLock<String>,
    superuser_openid: RwLock<String>,
    superuser_verify_timestamp: RwLock<DateTime<Utc>>,
}

impl SuperUserState {
    pub fn new(totp_gen: TOTP) -> Self {
        Self {
            totp_gen,
            last_totp_code: RwLock::default(),
            superuser_openid: RwLock::default(),
            superuser_verify_timestamp: RwLock::default(),
        }
    }

    pub fn verify_totp_challenge(&self, challenge: &str) -> Result<(), String> {
        let totp = get_totp();

        if totp.is_err() {
            let err_msg = format!("创建TOTP生成器失败：{}", totp.unwrap_err().to_string());
            tracing::log::warn!("{}", err_msg);
            return Err(err_msg);
        }

        let totp_code = totp.unwrap().generate_current();
        if totp_code.is_err() {
            let err_msg = format!(
                "生成TOTP Challenge失败：{}",
                totp_code.unwrap_err().to_string()
            );
            tracing::log::warn!("{}", err_msg);
            return Err(err_msg);
        }

        if challenge == *self.last_totp_code.read().unwrap() {
            Err("无法执行：此TOTP Challenge刚刚成功使用过。".into())
        } else {
            *self.last_totp_code.write().unwrap() = challenge.into();
            *self.superuser_verify_timestamp.write().unwrap() = Utc::now();
            Ok(())
        }
    }

    pub fn verify_superuser_privilege_group(&self, author_openid: &str) -> Result<(), String> {
        if *self.superuser_verify_timestamp.read().unwrap() + chrono::Duration::minutes(30)
            < Utc::now()
        {
            Err("上次验证已超过30分钟时限，请重新使用“su <TOTP Challenge>”验证。".into())
        } else if author_openid == self.superuser_openid.read().unwrap().as_str() {
            Ok(())
        } else {
            Err("用户没有超级用户权限".into())
        }
    }
}