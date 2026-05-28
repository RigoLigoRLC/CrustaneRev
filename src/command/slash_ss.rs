use std::sync::Arc;
use async_trait::async_trait;
use itertools::Itertools;
use tokio::{join, try_join};
use tokio::sync::Mutex;
use tracing::info;
use crate::backend::backend::{Backend, StickerRecipient};
use crate::command::BotCommand;
use crate::error_glue::CrustaneError;
use crate::utils::{get_group_openid_group_msg, get_sender_openid_group_msg, reply_group_simple, reply_group_simple_str, reply_group_with_media};
use crate::utils::wrappers::{CommonMessage, SeqCounter};

pub struct SlashSs;

#[async_trait::async_trait]
impl BotCommand for SlashSs {
    fn cmd_prefix(&self) -> &'static str {
        "/ss"
    }

    async fn trigger(&self, backend: Arc<Mutex<Backend>>, msg: &CommonMessage) -> Result<(), CrustaneError> {
        // Sticker search -
        // /sa keyword
        let mut seq = SeqCounter { count: 0 };
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
                    msg.reply_plain_with_seq("查询的关键词没有任何匹配项。".into(), None, Some(&mut seq)).await
                } else {
                    let len = result.len();
                    let candidate = result.into_iter().next().unwrap();

                    // Check if Tencent cache is hit
                    let cache_result = backend.lock().await.sticker_upload_cache_check(
                        candidate.id,
                        msg.msg.msg_type()
                    ).await?;

                    let media = if cache_result.is_some() {
                        // Cache hit. Extract media object
                        Some(cache_result.unwrap())
                    } else {
                        // Cache not hit. Send prompt about uploading so user can wait
                        let backend = backend.lock().await;
                        let (_, media_result) = join!(
                            msg.reply_plain_with_seq(format!("找到{}个结果，正在上传首选表情……", len), None, Some(&mut seq)),
                            backend.sticker_upload_to_tencent(
                                &msg.context,
                                msg.msg.msg_type(),
                                msg.msg.source_openid()?,
                                candidate.id,
                                candidate.filename,
                            )
                        );

                        match media_result {
                            Ok(media) => Some(media),
                            Err(e) => {
                                result_str = format!(
                                    "{}\n\n无法将首选图片上传。原因：{}",
                                    result_str, e
                                );
                                None
                            }
                        }
                    };

                    msg.reply_plain_with_seq(result_str, media, Some(&mut seq)).await
                }
            }
            Err(e) => msg.reply_plain_with_seq(e, None, Some(&mut seq)).await,
        }
    }
}
