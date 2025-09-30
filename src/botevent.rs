use std::sync::RwLock;
use std::ops::Deref;
use botrs::{Context, EventHandler, GroupMessage, GroupMessageParams, Media, Ready};
use chrono::{DateTime, Utc};
use chrono::format::parse;
use futures::StreamExt;
use tracing::{error, info, warn};
use crate::{backend, command, utils};
use crate::backend::backend::{Backend, StickerLiberatorOperation, StickerRecipient};
use crate::init::initialize_backend;
use once_cell::sync::OnceCell;
use regex::Regex;
use serde_json::Value;
use size::Size;
use sqlx::query;
use crate::utils::{get_totp, get_group_openid_group_msg, reply_group_simple, reply_group_simple_str, sec_to_duration_dhms, get_sender_openid_group_msg, reply_group_with_media};
use crate::backend::backend::StickerDomain;
use crate::error_glue::CrustaneError;

pub struct BotEventHandler {
    backend: OnceCell<Backend>,
    backend_init_msg: RwLock<String>,
    backend_init_called: RwLock<bool>,

    last_totp_code: RwLock<String>,
    superuser_openid: RwLock<String>,
    superuser_verify_timestamp: RwLock<DateTime<Utc>>,

    facetype_garbage_regex: Regex,
}

#[async_trait::async_trait]
impl EventHandler for BotEventHandler {
    async fn ready(&self, _ctx: Context, ready: Ready) {
        info!("Bot {} is ready!", ready.user.username);

        match self.backend_init().await {
            Ok(_) => info!("Backend initialized."),
            Err(e) => warn!("Backend initialization failed: {}", e),
        }
    }

    async fn group_message_create(&self, ctx: Context, message: GroupMessage) {
        if let Some(content) = &message.content {
            let params = match utils::msg_content_split_str(content.trim()) {
                Ok(params) => params,
                Err(e) => {
                    if let Err(e) = message.reply(
                        ctx.api.as_ref(),
                        &ctx.token,
                        format!("字符串参数解析出错：\n{}", e).as_str()).await {
                        warn!("回复错误信息失败：{}", e);
                    }
                    return
                }
            };

            if let Err(e) = self.dispatch_call_from_group(ctx, message, params).await {
                warn!("群消息分发时出错：{}", e);
            }
        }
    }
}

impl Default for BotEventHandler {
    fn default() -> Self {
        Self {
            backend: OnceCell::new(),
            backend_init_msg: RwLock::default(),
            backend_init_called: RwLock::default(),
            last_totp_code: RwLock::default(),
            superuser_openid: RwLock::default(),
            superuser_verify_timestamp: RwLock::default(),
            facetype_garbage_regex: Regex::new(r#"<faceType=.+?>"#).unwrap(),
        }
    }
}

impl BotEventHandler {
    /// Must call backend_init when you needed backend.
    /// Panicking in this function is your fault.
    fn backend(&self) -> &Backend {
        self.backend.get().unwrap()
    }

    async fn backend_init(&self) -> Result<(), String> {
        if let Some(_) = self.backend.get() {
            // Do not initialize twice
            Ok(())
        } else if *self.backend_init_called.read().unwrap() {
            // If init was called, don't try initializing automatically. Error out if it had failed.
            if self.backend.get().is_none() {
                Err(self.backend_init_msg.read().unwrap().clone())
            } else {
                Ok(())
            }
        } else {
            *self.backend_init_called.write().unwrap() = true;
            match initialize_backend().await {
                Ok(backend) => {
                    self.backend.get_or_init(|| backend);
                    Ok(())
                }
                Err(e) => {
                    *self.backend_init_msg.write().unwrap() = e;
                    Err(self.backend_init_msg.read().unwrap().deref().clone())
                }
            }
        }
    }

    fn verify_totp_challenge(&self, challenge: &str) -> Result<(), String> {
        let totp = get_totp();

        if totp.is_err() {
            let err_msg = format!("创建TOTP生成器失败：{}", totp.unwrap_err().to_string());
            tracing::log::warn!("{}", err_msg);
            return Err(err_msg);
        }

        let totp_code = totp.unwrap().generate_current();
        if totp_code.is_err() {
            let err_msg = format!("生成TOTP Challenge失败：{}", totp_code.unwrap_err().to_string());
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

    fn verify_superuser_privilege_group(&self, message: &GroupMessage) -> Result<bool, String> {
        if *self.superuser_verify_timestamp.read().unwrap() + chrono::Duration::minutes(30) < Utc::now() {
            Err("上次验证已超过30分钟时限，请重新使用“su <TOTP Challenge>”验证。".into())
        } else {
            Ok(get_sender_openid_group_msg(message)? == *self.superuser_openid.read().unwrap())
        }
    }

    async fn dispatch_call_from_group(&self, ctx: Context, message: GroupMessage, mut params: Vec<String>) -> Result<(), String> {
        if params.is_empty() {
            return Ok(reply_group_simple_str(&ctx, &message, "请输入命令").await?);
        }

        match params.remove(0).as_str() {
            "ping" => reply_group_simple(
                &ctx, &message,
                format!(
                    "Pong! \nPing 请求耗费了 {} ms 到达 Bot 端。",
                    (Utc::now() - message.timestamp.ok_or("时间戳为None")?).num_milliseconds()
                )
            ).await,

            "host" => {
                let sys = sysinfo::System::new_all();
                reply_group_simple(
                    &ctx, &message, format!(
                        "\n主机名：{}\n执行用户：{}\nRAM：{}/{}\n主机已运行时长：{}",
                        sysinfo::System::host_name().map_or(String::from("<无法获得主机名>"), |s| s),
                        whoami::username(),
                        Size::from_bytes(sys.used_memory()),
                        Size::from_bytes(sys.total_memory()),
                        sec_to_duration_dhms(sysinfo::System::uptime())
                    ),
                ).await
            },

            "su" => 'su: {
                // su - verify superuser identity
                // su exit/<totp challenge>
                if params.len() != 1 {
                    break 'su reply_group_simple_str(&ctx, &message, "必须携带一个参数：exit，或者TOTP Challenge。").await;
                }

                if params[0] == "exit" {
                    (*self.superuser_openid.write().unwrap()).clear();
                    reply_group_simple_str(&ctx, &message, "您已退出超级用户状态。").await
                } else {
                    match self.verify_totp_challenge(params[0].as_str()) {
                        Ok(_) => {
                            (*self.superuser_openid.write().unwrap()).push_str(get_sender_openid_group_msg(&message)?);
                            reply_group_simple_str(&ctx, &message, "您已成功验证超级用户权限。此状态可自动在进行特权操作后维持30分钟。").await
                        }
                        Err(e) => reply_group_simple(&ctx, &message, e).await
                    }
                }
            }

            "purge_db" => 'purge_db: {
                match self.verify_superuser_privilege_group(&message) {
                    Ok(is_su) => {
                        if !is_su {
                            break 'purge_db reply_group_simple_str(&ctx, &message, "您不是验证的超级用户，无法执行。").await
                        }
                        reply_group_simple_str(&ctx, &message, "还没实现").await
                    },
                    Err(e) => reply_group_simple(&ctx, &message, e).await
                }
            }

            "liberator" => 'liberator: {
                // liberator - become/quit as a liberator.
                // liberator become/quit <TOTP Challenge>
                let usage = || reply_group_simple_str(&ctx, &message, "liberator become/quit <TOTP Challenge>");
                if params.len() > 2 || params.is_empty() {
                    break 'liberator usage().await
                }

                let openid = get_sender_openid_group_msg(&message)?;
                let verification = match self.backend().sticker_liberator_ops(openid, StickerLiberatorOperation::Verify).await {
                    Ok(verification) => verification,
                    Err(e) => break 'liberator Err(e)
                };

                match params[0].as_str() {
                    "become" => {
                        match self.verify_totp_challenge(params[1].as_str()) {
                            Ok(()) => {
                                if verification != 0 {
                                    reply_group_simple_str(&ctx, &message, "您已经是解放者了。").await
                                } else {
                                    match self.backend().sticker_liberator_ops(openid, StickerLiberatorOperation::Add).await {
                                        Ok(_) => reply_group_simple_str(&ctx, &message, "您成为了解放者；您今后上传的表情包所有人都将可搜索。\n如您想将以往的表情包都变为所有人可搜索的状态，请使用“liberate”命令。").await,
                                        Err(e) => reply_group_simple(&ctx, &message, format!("无法成为解放者：{}", e)).await,
                                    }
                                }
                            }
                            Err(e) => {
                                reply_group_simple(&ctx, &message, format!("无法成为解放者：TOTP验证失败：{}", e)).await
                            }
                        }
                    }
                    "quit" => {
                        if verification != 0 {
                            match self.backend().sticker_liberator_ops(openid, StickerLiberatorOperation::Remove).await {
                                Ok(_) => reply_group_simple_str(&ctx, &message, "您已不再是解放者。").await,
                                Err(e) => reply_group_simple(&ctx, &message, format!("无法成为解放者：{}", e)).await,
                            }
                        } else {
                            reply_group_simple_str(&ctx, &message, "您已经是解放者了。").await
                        }
                    }
                    _ => break 'liberator usage().await,
                }

            }

            "liberate" => 'liberate: {
                // liberate - liberate all of the user's stickers. The user must have already
                // become a liberator or be verified as superuser.
                // A liberator can liberate his own stickers. The superuser can liberate any sticker
                // with an ID.
                // liberate [id]
                // If no ID is provided, the current verified user's all stickers will be liberated.
                let openid = get_sender_openid_group_msg(&message)?;
                let is_superuser =  match self.verify_superuser_privilege_group(&message) {
                    Ok(is_su) => is_su,
                    Err(e) => break 'liberate reply_group_simple(&ctx, &message, e).await
                };
                let is_liberator = match self.backend().sticker_liberator_ops(openid, StickerLiberatorOperation::Verify).await {
                    Ok(n) => n != 0,
                    Err(e) => break 'liberate reply_group_simple(&ctx, &message, e.into()).await
                };
                if !is_superuser && !is_liberator {
                    break 'liberate reply_group_simple_str(&ctx, &message, "您无权公有化您的表情包。只有超级用户或者经过TOTP验证的解放者有权操作。").await;
                }

                if params.len() == 0 {
                    let openid = get_sender_openid_group_msg(&message)?;
                    match self.backend().sticker_liberate_all(openid).await {
                        Ok(count) => reply_group_simple(&ctx, &message, format!("公有化了{}个表情包。", count)).await,
                        Err(e) => reply_group_simple(&ctx, &message, e).await,
                    }
                } else if params.len() == 1 {
                    let id = match params[0].parse::<i64>() {
                        Ok(id) => id,
                        Err(e) => break 'liberate reply_group_simple(&ctx, &message, format!("参数指定的ID无法转换为i64：{}", e)).await
                    };

                    if !match self.backend().sticker_exists(id).await {
                        Ok(x) => x,
                        Err(e) => break 'liberate reply_group_simple(&ctx, &message, e).await,
                    } {
                        break 'liberate reply_group_simple(&ctx, &message, format!("不存在ID={}的表情包。", id)).await
                    }
                    match self.backend().sticker_liberate_one(is_superuser, openid, id).await {
                        Ok(()) => reply_group_simple(&ctx, &message, format!("公有化了ID={}的表情包。", id)).await,
                        Err(e) => reply_group_simple(&ctx, &message, e).await,
                    }
                } else {
                    break 'liberate reply_group_simple_str(&ctx, &message, "liberate [表情ID]").await;
                }
            }

            "/su" => '_su: {
                // Sticker Upload -
                // /su [.u/.user/.g/.group] tag [..tags] WithOneImageAttachment
                self.backend_init().await?;

                // Ensure exactly one image attachment
                if message.attachments.len() != 1 {
                    break '_su reply_group_simple_str(&ctx, &message, "需要在消息中附带1个图片才可使用。").await;
                }

                // Get the corresponding OpenID for the specified domain
                let domain = if params.len() >= 2 && params[0].starts_with(".") {
                    let ret = match &params[0][1..] {
                        "g" | "group" => StickerDomain::Group,
                        "u" | "user" | _ => StickerDomain::User,
                    };
                    params.remove(0); // Get rid of the domain specifier
                    ret
                } else { StickerDomain::User };
                let uploader_openid = get_sender_openid_group_msg(&message)?;
                let domain_openid = match domain {
                    StickerDomain::Group => get_group_openid_group_msg(&message)?,
                    StickerDomain::User => uploader_openid,
                };

                // After removing domain specifier, there should be at least one argument left
                if params.len() == 0 {
                    break '_su reply_group_simple(&ctx, &message, "必须为表情图片指定标签才可添加。".into()).await
                }

                // Join all specified tags with space
                let tags = params.join(" ");

                // Remove potential garbage data like "<faceType=6, faceId=0, ext=...>"
                // This may happen if user inserted QQ Stickers inside the text
                let tags = self.facetype_garbage_regex.replace_all(tags.as_str(), "").to_string();

                // Generate a UUID as the image file name
                let atta = message.attachments.first().unwrap();
                let filename = format!(
                    "{}.{}",
                    uuid::Uuid::new_v4().to_string(),
                    if atta.content_type.as_ref().is_none() { "jpg" } else {
                        let content_type = atta.content_type.as_ref().unwrap();
                        content_type.split('/').last().unwrap()
                    }
                );

                match self.backend().handle_sticker_upload(
                    atta.url.as_ref().unwrap(), filename, domain_openid, uploader_openid, tags
                ).await {
                    Ok(id) => reply_group_simple(&ctx, &message, format!("成功添加了一个表情，ID={}。", id)).await,
                    Err(e) => reply_group_simple(&ctx, &message, format!("添加表情错误：{}", e)).await
                }
            }

            "/ss" => '_ss: {
                // Sticker search -
                // /sa keyword

                if params.len() == 0 {
                    break '_ss reply_group_simple_str(&ctx, &message, "必须指定搜索关键字。").await;
                }

                match self.backend().sticker_query_simple(
                    params.join(" "),
                    get_sender_openid_group_msg(&message)?,
                    get_group_openid_group_msg(&message)?
                ).await {
                    Ok(result) => {
                        let mut result_str = result
                            .iter()
                            .map(|it| format!("ID={} Tag=“{}”", it.id, it.tags))
                            .collect::<Vec<String>>()
                            .join("\n");

                        info!("查询结果：\n{}", result_str);

                        if result.is_empty() {
                            reply_group_simple_str(&ctx, &message, "查询的关键词没有任何匹配项。").await
                        } else {
                            let candidate = result.into_iter().next().unwrap();
                            let media = match self.backend().sticker_upload_to_tencent(
                                &ctx,
                                StickerRecipient::Group,
                                get_group_openid_group_msg(&message)?,
                                candidate.id,
                                candidate.filename
                            ).await {
                                Ok(media) => Some(media),
                                Err(e) => {
                                    result_str = format!("{}\n\n无法将首选图片上传。原因：{}", result_str, e);
                                    None
                                }
                            };

                            reply_group_with_media(&ctx, &message, result_str, media).await
                        }
                    },
                    Err(e) => reply_group_simple(&ctx, &message, e).await
                }
            }

            "ssi" => 'ssi: {
                if params.len() == 0 {
                    break 'ssi reply_group_simple_str(&ctx, &message, "必须指定搜索关键字。").await;
                }

                match self.backend().sticker_id_query_domainless(params.join(" ")).await {
                    Ok(result) => {
                        let result = result
                            .iter()
                            .map(|it| format!("ID={}", it))
                            .collect::<Vec<String>>()
                            .join("\n");
                        info!("查询结果：\n{}", result);
                        reply_group_simple(&ctx, &message, result).await
                    },
                    Err(e) => {
                        error!("数据库操作失败\n{}", e);
                        reply_group_simple(&ctx, &message, e).await
                    }
                }
            }

            unknown => reply_group_simple(&ctx, &message, format!("未知的指令：{}", unknown)).await
        }?;

        Ok(())
    }
}
