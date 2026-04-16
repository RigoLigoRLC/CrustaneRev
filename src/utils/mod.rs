pub mod wrappers;

use crate::error_glue::CrustaneError;
use botrs::{
    C2CMessage, C2CMessageParams, Context, GroupMessage, GroupMessageParams, Media,
    MessageReference, Reference,
};
use futures::stream::StreamExt;
use std::env;
use std::ops::Range;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use totp_rs::{Algorithm, Secret, TOTP};

pub(crate) fn msg_content_split_spans(content: &str) -> Result<Vec<Range<usize>>, CrustaneError> {
    let mut ret = Vec::new();
    let mut begin: usize = 0;
    let mut in_str = false;
    let mut after_backslash = false;

    for (char_pos, (i, c)) in content.char_indices().enumerate() {
        if in_str {
            if after_backslash {
                after_backslash = false;
                match c {
                    '\\' => continue,
                    '"' => continue,
                    other => {
                        return Err(format!(
                            "非法转义序列 \\'{}' （位于第 {} 字符处）",
                            other, char_pos
                        )
                        .into());
                    }
                }
            } else if c == '"' {
                in_str = false;
            }
        } else if c == '"' {
            in_str = true;
        } else if c == ' ' {
            ret.push(begin..i);
            begin = i + 1;
        }
    }

    if begin != content.len() {
        ret.push(begin..content.len());
    }

    Ok(ret)
}

pub(crate) fn msg_content_split_str<'a>(content: &'a str) -> Result<Vec<&'a str>, CrustaneError> {
    Ok(msg_content_split_spans(content)?
        .into_iter()
        .map(|span| &content[span])
        .collect())
}

pub(crate) fn get_group_openid_group_msg(message: &GroupMessage) -> Result<&str, CrustaneError> {
    if message.group_openid.is_none() {
        Err("内部错误：message.group_openid为None".into())
    } else {
        Ok(message.group_openid.as_ref().unwrap().as_str())
    }
}

pub(crate) fn get_sender_openid_group_msg(message: &GroupMessage) -> Result<&str, CrustaneError> {
    if message.author.is_none() {
        Err("内部错误：message.author为None".into())
    } else if message.author.as_ref().unwrap().member_openid.is_none() {
        Err("内部错误：message.author.member_openid为None".into())
    } else {
        Ok(message
            .author
            .as_ref()
            .unwrap()
            .member_openid
            .as_ref()
            .unwrap()
            .as_str())
    }
}

pub(crate) async fn reply_group_simple(
    ctx: &Context,
    message: &GroupMessage,
    reply_content: String,
) -> Result<(), CrustaneError> {
    let msg_id_str = message
        .id
        .as_deref()
        .ok_or("message.id 为 None")?
        .to_string();
    let params = GroupMessageParams {
        msg_type: 0,
        content: Some(reply_content),
        msg_id: Some(msg_id_str.clone()),
        message_reference: Some(Reference {
            message_id: Some(msg_id_str),
            ignore_get_message_error: Some(true),
        }),
        ..Default::default()
    };

    ctx.api
        .post_group_message_with_params(
            &ctx.token,
            message
                .group_openid
                .as_deref()
                .ok_or("message.group_openid 为 None")?,
            params,
        )
        .await?;

    Ok(())
}

pub(crate) async fn reply_group_with_media(
    ctx: &Context,
    message: &GroupMessage,
    reply_content: String,
    media: Option<Media>,
) -> Result<(), CrustaneError> {
    let msg_id_str = message
        .id
        .as_deref()
        .ok_or("message.id 为 None")?
        .to_string();
    let params = GroupMessageParams {
        msg_type: 7,
        content: Some(reply_content),
        msg_id: Some(msg_id_str.clone()),
        message_reference: Some(Reference {
            message_id: Some(msg_id_str),
            ignore_get_message_error: Some(true),
        }),
        media,
        ..Default::default()
    };

    ctx.api
        .post_group_message_with_params(
            &ctx.token,
            message
                .group_openid
                .as_deref()
                .ok_or("message.group_openid 为 None")?,
            params,
        )
        .await?;

    Ok(())
}

pub(crate) async fn reply_group_simple_str(
    ctx: &Context,
    message: &GroupMessage,
    reply_content: &str,
) -> Result<(), CrustaneError> {
    let msg_id_str = message
        .id
        .as_deref()
        .ok_or("message.id 为 None")?
        .to_string();
    let params = GroupMessageParams {
        msg_type: 0,
        content: Some(String::from(reply_content)),
        msg_id: Some(msg_id_str.clone()),
        message_reference: Some(Reference {
            message_id: Some(msg_id_str),
            ignore_get_message_error: Some(true),
        }),
        ..Default::default()
    };

    ctx.api
        .post_group_message_with_params(
            &ctx.token,
            message
                .group_openid
                .as_deref()
                .ok_or("message.group_openid 为 None")?,
            params,
        )
        .await?;

    Ok(())
}

pub(crate) async fn reply_c2c_simple(
    ctx: &Context,
    message: &C2CMessage,
    reply_content: String,
) -> Result<(), CrustaneError> {
    let params = C2CMessageParams {
        msg_type: 0,
        content: Some(reply_content),
        msg_id: Some(
            message
                .id
                .as_deref()
                .ok_or("message.id 为 None")?
                .to_string(),
        ),
        ..Default::default()
    };

    ctx.api
        .post_c2c_message_with_params(
            &ctx.token,
            message
                .author
                .as_ref()
                .ok_or("message.author 为 None")?
                .user_openid
                .as_ref()
                .ok_or("message.author.user_openid 为 None")?
                .as_ref(),
            params,
        )
        .await?;

    Ok(())
}

pub(crate) async fn reply_c2c_simple_str(
    ctx: &Context,
    message: &C2CMessage,
    reply_content: &str,
) -> Result<(), CrustaneError> {
    let params = C2CMessageParams {
        msg_type: 0,
        content: Some(String::from(reply_content)),
        msg_id: Some(
            message
                .id
                .as_deref()
                .ok_or("message.id 为 None")?
                .to_string(),
        ),
        ..Default::default()
    };

    ctx.api
        .post_c2c_message_with_params(
            &ctx.token,
            message
                .author
                .as_ref()
                .ok_or("message.author 为 None")?
                .user_openid
                .as_ref()
                .ok_or("message.author.user_openid 为 None")?
                .as_ref(),
            params,
        )
        .await?;

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
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Raw(env::var("QQ_BOT_SECRET")?.as_bytes().to_vec())
            .to_bytes()
            .unwrap(),
        Some("RigoLigo Creations".to_string()),
        "CrustaneRev Admin".to_string(),
    )?)
}

/// Say thanks to Google AI Overview and RustRover
/// I couldn't have finished this function by myself
pub(crate) async fn download_file(url: &String, dest_file: &str) -> Result<(), CrustaneError> {
    let response = reqwest::get(url.as_str()).await?.error_for_status()?;

    let mut file = File::create(dest_file).await?;

    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        file.write_all(&chunk?).await?;
    }

    Ok(())
}
