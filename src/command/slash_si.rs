use std::sync::Arc;
use itertools::Itertools;
use tokio::sync::Mutex;
use crate::backend::backend::Backend;
use crate::command::BotCommand;
use crate::error_glue::CrustaneError;
use crate::utils::wrappers::CommonMessage;

pub struct SlashSi;

#[async_trait::async_trait]
impl BotCommand for SlashSi {
    fn cmd_prefix(&self) -> &'static str {
        "/si"
    }

    async fn trigger(&self, backend: Arc<Mutex<Backend>>, msg: &CommonMessage) -> Result<(), CrustaneError> {
        // Sticker Inspect -
        // /si <sticker_id> [optional_operation  [optional_parameters]]
        let help = || async {
            msg.reply_plain(
                concat!(
                    "/si - Sticker Inspection 表情图修改\n",
                    "  /si <ID> [可选操作 [可选参数 ...]]\n",
                    "  当未提供操作时，将显示此表情的详细信息；\n",
                    "可用的操作有：\n",
                    "  set-tag <新Tag> [<新Tag>...]\n",
                    "    为表情包设置新Tag。可指定一至多个Tag。Tag之间将用空格连接。",
                    "当您要对某个表情进行操作时，您必须是上传者本人或者超级用户。",
                ).to_string(),
                None
            ).await
        };
        let params = msg.params()?;

        // If only one param exists, it must be "/si". Display help and exit.
        if params.len() == 1 {
            return help().await;
        }

        // Skip "/si". Next next() call points to an ID
        let mut params = params.iter().peekable();
        params.next();

        // Try to resolve sticker ID. Next next() call points to an optional sub-command
        let id = match params.next().unwrap().parse::<i64>() {
            Ok(id) => id,
            Err(e) => {
                return msg.reply_plain("您输入的ID无法解析为整数。".to_string(), None).await;
            }
        };

        // Try to fetch sub-command. Next next() call will get a tag.
        let param_subcmd = params.next();
        if param_subcmd.is_none() {
            return match {
                backend.lock().await.sticker_inspect_simple(id).await
            } {
                Ok(result) => match result {
                    Some(result) => {
                        msg.reply_plain(
                            format!(
                                concat!(
                                    "ID={}\n",
                                    "Tags=\"{}\"\n",
                                    "上传于 {}\n\n",
                                    "所属域ID={}\n",
                                    "上传者ID={}\n",
                                    "view_level={}",
                                ),
                                id,
                                result.tags,
                                result.added_date,
                                result.domain_openid,
                                result.uploader_openid,
                                result.view_level
                            ),
                            None
                        ).await
                    }
                    None => msg.reply_plain("您输入的ID未匹配任何表情包。".to_string(), None).await
                },
                Err(e) => msg.reply_plain(e.into(), None).await,
            };
        }

        let sender_openid = msg.msg.author()?.member_or_openid()?;
        let uploader = match  {
            backend.lock().await.sticker_uploader_openid_query(id).await
        } {
            Ok(uploader) => uploader,
            Err(e) => {
                return msg.reply_plain(format!("查询表情包上传者失败：{}", e), None).await;
            }
        };

        let is_superuser = {
            backend.lock().await.superuser_state().verify_superuser_privilege_group(msg.msg.author()?.openid()?)
        };

        if uploader.as_str() != sender_openid && is_superuser.is_err() {
            return msg.reply_plain(
                format!(
                    "您不是表情包的上传者或者超级用户（{}），无法操作这个表情包。",
                    is_superuser.unwrap_err()
                ),
                None
            ).await;
        }

        match param_subcmd.unwrap() {
            "set-tag" => {
                if params.peek().is_none() {
                    return help().await;
                }
                let new_tag = params.join(" ");
                match { backend.lock().await.sticker_set_tags(id, new_tag.as_str()).await } {
                    Ok(_) => msg.reply_plain("成功修改了指定表情包的标签。".into(), None).await,
                    Err(e) => msg.reply_plain(e.into(), None).await,
                }
            }
            _ => help().await,
        }
    }
}
