use std::sync::Arc;
use itertools::Itertools;
use regex::Regex;
use tokio::sync::Mutex;
use crate::backend::backend::{Backend, StickerDomain};
use crate::command::BotCommand;
use crate::error_glue::CrustaneError;
use crate::utils::{get_group_openid_group_msg, get_sender_openid_group_msg, reply_group_simple, reply_group_simple_str};
use crate::utils::wrappers::CommonMessage;
use crate::utils::wrappers::{CommonMessage, WrappedMessage};

pub struct SlashSu {
    facetype_garbage_regex: Regex,
}

#[async_trait::async_trait]
impl BotCommand for SlashSu {
    fn cmd_prefix(&self) -> &'static str {
        "/su"
    }

    async fn trigger(&self, backend: Arc<Mutex<Backend>>, msg: &CommonMessage) -> Result<(), CrustaneError> {
        // Sticker Upload -
        // /su [.u/.user/.g/.group] tag [..tags] WithOneImageAttachment

        let params = msg.params()?;
        let mut param_cursor = 1usize;

        // Ensure exactly one image attachment
        let quoted_msg;
        let (atta_filename, atta_url) = if msg.msg.attachments()?.len() == 1 {
            let atta = msg.msg.attachments()?.first().unwrap();
            (atta.filename.as_ref().unwrap(), atta.url.as_ref().unwrap())
        } else if msg.msg.attachments()?.len() > 1 {
            // More than one image is provided
            return msg.reply_plain("需要在消息中附带1个图片才可使用。".into(), None).await;
        } else {
            // If no attachments found, check "msg_elements" for a quoted message
            match msg.msg.quoted_msg() {
                Ok(quote) => {
                    match quote {
                        None => {
                            // No quoted message
                            return msg.reply_plain("需要在消息中附带1个图片才可使用。".into(), None).await;
                        }
                        Some(quote) => {
                            quoted_msg = quote;
                            if quoted_msg.attachments()?.len() == 1 {
                                let atta = quoted_msg.attachments()?.first().unwrap();
                                (atta.filename.as_ref().unwrap(), atta.url.as_ref().unwrap())
                            } else {
                                return msg.reply_plain("需要在消息中附带1个图片才可使用。".into(), None).await;
                            }
                        }
                    }
                }
                Err(e) => {
                    // Parse failed
                    return msg.reply_plain(
                        format!("需要在消息中附带1个图片才可使用。\n\n引用消息解析失败：{}", e).into(),
                        None
                    ).await;
                }
            }
        };

        // Get the corresponding OpenID for the specified domain
        let domain = if params.len() >= 2 && params[param_cursor].starts_with(".") {
            let ret = match &params[param_cursor][1..] {
                "g" | "group" => StickerDomain::Group,
                "u" | "user" | _ => StickerDomain::User,
            };
            param_cursor += 1; // Get rid of the domain specifier
            ret
        } else {
            StickerDomain::User
        };

        let uploader_openid = msg.msg.author()?.member_or_openid()?;
        let domain_openid = msg.msg.source_openid()?;

        // After removing domain specifier, there should be at least one argument left
        if params.len() == param_cursor {
            // #[cfg(not(target_os = "macos"))]
            // {
                return msg.reply_plain("必须为表情图片指定标签才可添加。".into(), None).await;
            // }

            // #[cfg(target_os = "macos")]
            // {
            //     // Extract a tag with Vision.framework
            //
            //     let data = objc2_foundation::NSData::from_vec()
            // }
        }

        // Join all specified tags with space
        let tags = params.iter().skip(param_cursor).join(" ");

        // Remove potential garbage data like "<faceType=6, faceId=0, ext=...>"
        // This may happen if user inserted QQ Stickers inside the text
        let tags = self
            .facetype_garbage_regex
            .replace_all(tags.as_str(), "")
            .to_string();

        // Generate a UUID as the image file name
        let filename = format!(
            "{}.{}",
            uuid::Uuid::new_v4().to_string(),
            atta_filename.split('.').last().unwrap()
        );

        match backend.lock().await.handle_sticker_upload(
            &atta_url,
            filename,
            domain_openid,
            uploader_openid,
            tags,
        ).await {
            Ok(id) => msg.reply_plain(format!("成功添加了一个表情，ID={}。", id), None).await,
            Err(e) => msg.reply_plain(format!("添加表情错误：{}", e), None).await,
        }
    }
}

impl Default for SlashSu {
    fn default() -> Self {
        Self {
            facetype_garbage_regex: Regex::new(r#"<faceType=.+?>"#).unwrap()
        }
    }
}
