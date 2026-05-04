use std::sync::Arc;
use tokio::sync::Mutex;
use crate::backend::backend::{Backend, StickerLiberatorOperation};
use crate::command::BotCommand;
use crate::error_glue::CrustaneError;
use crate::utils::wrappers::CommonMessage;

pub struct Liberate;

#[async_trait::async_trait]
impl BotCommand for Liberate {
    fn cmd_prefix(&self) -> &'static str {
        "liberate"
    }

    async fn trigger(&self, backend: Arc<Mutex<Backend>>, msg: &CommonMessage) -> Result<(), CrustaneError> {
        // liberate - liberate all of the user's stickers. The user must have already
        // become a liberator or be verified as superuser.
        // A liberator can liberate his own stickers. The superuser can liberate any sticker
        // with an ID.
        // liberate [id]
        // If no ID is provided, the current verified user's all stickers will be liberated.
        let openid = msg.msg.author()?.member_or_openid()?;
        let mut auth_err_msg: String = String::new();
        let is_liberator = match backend.lock().await.sticker_liberator_ops(openid, StickerLiberatorOperation::Verify).await {
            Ok(n) => n != 0,
            Err(e) => {
                let e = e.to_string();
                auth_err_msg.push_str(e.as_str());
                false
            }
        };
        let is_superuser = backend.lock().await.superuser_state().verify_superuser_privilege_group(openid);
        if is_superuser.is_err() && !is_liberator {
            return msg.reply_plain(
                format!(
                    "您无权公有化您的表情包。只有超级用户或者经过TOTP验证的解放者有权操作（{}）。{}{}",
                    is_superuser.unwrap_err(),
                    if auth_err_msg.is_empty() { "" } else { "\n\n" },
                    auth_err_msg
                ),
                None
            ).await;
        }

        let params = msg.params()?;
        if params.len() == 1 {
            match backend.lock().await.sticker_liberate_all(openid).await {
                Ok(count) => {
                    msg.reply_plain(
                        format!("公有化了{}个表情包。", count),
                        None,
                    ).await
                }
                Err(e) => msg.reply_plain(e, None).await,
            }
        } else if params.len() == 2 {
            let id = match params[1].parse::<i64>() {
                Ok(id) => id,
                Err(e) => {
                    return msg.reply_plain(
                        format!("参数指定的ID无法转换为i64：{}", e),
                        None,
                    ).await;
                }
            };

            if !match backend.lock().await.sticker_exists(id).await {
                Ok(x) => x,
                Err(e) => return msg.reply_plain(e, None).await,
            } {
                return msg.reply_plain(
                    format!("不存在ID={}的表情包。", id),
                    None,
                ).await;
            }
            match backend.lock().await.sticker_liberate_one(is_superuser.is_ok(), openid, id).await {
                Ok(()) => {
                    msg.reply_plain(
                        format!("公有化了ID={}的表情包。", id),
                        None,
                    ).await
                }
                Err(e) => msg.reply_plain(e, None).await,
            }
        } else {
            msg.reply_plain("liberate [表情ID]".into(), None).await
        }
    }
}
