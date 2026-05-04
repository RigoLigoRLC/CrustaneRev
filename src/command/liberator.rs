use std::sync::Arc;
use tokio::sync::Mutex;
use crate::backend::backend::{Backend, StickerLiberatorOperation};
use crate::command::BotCommand;
use crate::error_glue::CrustaneError;
use crate::utils::wrappers::CommonMessage;

pub struct Liberator;

#[async_trait::async_trait]
impl BotCommand for Liberator {
    fn cmd_prefix(&self) -> &'static str {
        "liberator"
    }

    async fn trigger(&self, backend: Arc<Mutex<Backend>>, msg: &CommonMessage) -> Result<(), CrustaneError> {
        // liberator - become/quit as a liberator.
        // liberator become/quit <TOTP Challenge>
        let usage = || {
            msg.reply_plain("liberator become/quit <TOTP Challenge>".into(), None)
        };

        let params = msg.params()?;

        if params.len() > 3 || params.len() < 2 {
            return usage().await;
        }

        let openid = msg.msg.author()?.member_or_openid()?;
        let verification = match backend.lock().await.sticker_liberator_ops(openid, StickerLiberatorOperation::Verify).await {
            Ok(verification) => verification,
            Err(e) => return Err(e),
        };

        match &params[1] {
            "become" => {
                match backend.lock().await.superuser_state().verify_totp_challenge(&params[2]) {
                    Ok(()) => {
                        if verification != 0 {
                            msg.reply_plain("您已经是解放者了。".into(), None).await
                        } else {
                            match backend.lock().await.sticker_liberator_ops(openid, StickerLiberatorOperation::Add).await {
                                Ok(_) => msg.reply_plain("您成为了解放者；您今后上传的表情包所有人都将可搜索。\n如您想将以往的表情包都变为所有人可搜索的状态，请使用“liberate”命令。".into(), None).await,
                                Err(e) => msg.reply_plain(format!("无法成为解放者：{}", e), None).await,
                            }
                        }
                    }
                    Err(e) => {
                        msg.reply_plain(format!("无法成为解放者：TOTP验证失败：{}", e), None).await
                    }
                }
            },
            "quit" => {
                if verification != 0 {
                    match backend.lock().await.sticker_liberator_ops(openid, StickerLiberatorOperation::Remove).await {
                        Ok(_) => {
                            msg.reply_plain("您已不再是解放者。".into(), None).await
                        }
                        Err(e) => {
                            msg.reply_plain(format!("无法成为解放者：{}", e).into(), None).await
                        }
                    }
                } else {
                    msg.reply_plain("您已经是解放者了。".into(), None).await
                }
            }
            _ => return usage().await,
        }

    }
}