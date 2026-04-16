use std::sync::Arc;
use async_trait::async_trait;
use itertools::Itertools;
use tokio::sync::Mutex;
use tracing::info;
use crate::backend::backend::{Backend, StickerRecipient};
use crate::command::BotCommand;
use crate::error_glue::CrustaneError;
use crate::utils::{get_group_openid_group_msg, get_sender_openid_group_msg, reply_group_simple, reply_group_simple_str, reply_group_with_media};
use crate::utils::wrappers::CommonMessage;

pub struct SlashSs;

#[async_trait::async_trait]
impl BotCommand for SlashSs {
    fn cmd_prefix(&self) -> &'static str {
        "/ss"
    }

    async fn trigger(&self, backend: Arc<Mutex<Backend>>, msg: &CommonMessage) -> Result<(), CrustaneError> {
        // Sticker search -
        // /sa keyword
        let params = msg.params()?;
        if params.len() == 1 {
            return msg.reply_plain("必须指定搜索关键字。".into(), None).await;
        }

        let query_content = params.iter().skip(1).join(" ");

        match {
            backend.lock().await.sticker_query_simple(
                query_content,
                msg.msg.author()?.member_or_openid()?,
                msg.msg.source_openid()?,
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
                    msg.reply_plain("查询的关键词没有任何匹配项。".into(), None).await
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
