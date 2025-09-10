use std::env;
use botrs::{Context, GroupMessage, GroupMessageParams, Message};
use totp_rs::{Algorithm, Secret, TOTP};
use crate::error_glue::CrustaneError;

pub(crate) fn msg_content_split_str(content: &str) -> Result<Vec<String>, CrustaneError> {
    let mut ret: Vec<String> = Vec::new();
    let mut segment: String = String::new();
    let mut in_str = false;
    let mut after_backslash = false;

    for (i, c) in content.chars().enumerate() {
        if in_str {
            if after_backslash {
                after_backslash = false;
                match c {
                    '\\' => segment.push('\\'),
                    '"'  => segment.push('"'),
                    other => {
                        return Err(format!("非法转义序列 \\'{}' （位于第 {} 字符处）", other, i).into());
                    }
                }
            } else if c == '"' {
                in_str = false;
            } else {
                segment.push(c);
            }
        } else if c == '"' {
            in_str = true;
        } else if c == ' ' {
            ret.push(segment.clone());
            segment.clear();
        } else {
            segment.push(c);
        }
    }

    if segment.len() != 0 {
        ret.push(segment);
    }

    Ok(ret)

}

pub(crate) fn msg_content_split(content: &String) -> Result<Vec<String>, CrustaneError> {
    msg_content_split_str(content.as_str())
}

pub(crate) async fn reply_group_simple(ctx: &Context, message: &GroupMessage, reply_content: String) -> Result<(), CrustaneError> {
    let params = GroupMessageParams {
        msg_type: 0,
        content: Some(reply_content),
        msg_id: Some(message.id.as_deref().ok_or("message.id 为 None")?.to_string()),
        ..Default::default()
    };

    ctx.api.post_group_message_with_params(
        &ctx.token,
        message.group_openid.as_deref().ok_or("message.group_openid 为 None")?,
        params
    ).await?;

    Ok(())
}

pub(crate) async fn reply_group_simple_str(ctx: &Context, message: &GroupMessage, reply_content: &str) -> Result<(), CrustaneError> {
    let params = GroupMessageParams {
        msg_type: 0,
        content: Some(String::from(reply_content)),
        msg_id: Some(message.id.as_deref().ok_or("message.id 为 None")?.to_string()),
        ..Default::default()
    };

    ctx.api.post_group_message_with_params(
        &ctx.token,
        message.group_openid.as_deref().ok_or("message.group_openid 为 None")?,
        params
    ).await?;

    Ok(())
}

pub(crate) fn sec_to_duration_dhms(secs: u64) -> String {
    let days = secs / 86400;
    let secs = secs % 86400;
    let hours = secs / 3600;
    let secs = secs % 3600;
    let minutes = secs / 60;
    let secs = secs % 60;
    if days > 0 {
        format!("{} 天 {:02}:{:02}:{:02}", days, hours, minutes, secs)
    } else {
        format!("{:02}:{:02}:{:02}", days, hours, minutes)
    }
}

pub(crate) fn get_totp() -> Result<TOTP, CrustaneError> {
    Ok(TOTP::new(
        Algorithm::SHA1, 6, 1, 30,
        Secret::Raw(env::var("QQ_BOT_SECRET")?.as_bytes().to_vec()).to_bytes().unwrap(),
        Some("RigoLigo Creations".to_string()),
        "CrustaneRev Admin".to_string()
    )?)
}
