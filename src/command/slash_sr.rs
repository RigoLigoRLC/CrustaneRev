use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;
use crate::backend::backend::Backend;
use crate::command::BotCommand;
use crate::error_glue::CrustaneError;
use crate::utils::wrappers::CommonMessage;

pub struct SlashSr;

#[async_trait::async_trait]
impl BotCommand for SlashSr {
    fn cmd_prefix(&self) -> &'static str {
        "/sr"
    }

    async fn trigger(&self, backend: Arc<Mutex<Backend>>, msg: &CommonMessage) -> Result<(), CrustaneError> {
        // Sticker Random - randomly select a sticker

        match {
            backend.lock().await.sticker_query_random(
                msg.msg.author()?.member_or_openid()?,
                msg.msg.source_openid()?,
                1
            ).await
        } {
            Ok(result) => {
                let mut result_str = result
                    .iter()
                    .map(|it| format!("ID={} Tag=“{}”", it.id, it.tags))
                    .collect::<Vec<String>>()
                    .join("\n");

                info!("查询结果：\n{}", result_str);

                if result.is_empty() {
                    msg.reply_plain("没有表情包被选中。可能是由于表情库是空的。".into(), None).await
                } else {
                    let candidate = result.into_iter().next().unwrap();
                    let media = match {
                        backend.lock().await.sticker_upload_to_tencent(
                            &msg.context,
                            msg.msg.msg_type(),
                            msg.msg.source_openid()?,
                            candidate.id,
                            candidate.filename,
                        ).await
                    } {
                        Ok(media) => Some(media),
                        Err(e) => {
                            result_str = format!(
                                "{}\n\n无法将首选图片上传。原因：{}",
                                result_str, e
                            );
                            None
                        }
                    };

                    msg.reply_plain(result_str, media).await
                }
            }
            Err(e) => msg.reply_plain(e, None).await,
        }
    }
}

