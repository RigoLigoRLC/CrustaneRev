use std::sync::RwLock;
use std::ops::Deref;
use botrs::{Context, EventHandler, GroupMessage, Ready};
use chrono::Utc;
use tracing::{info, warn};
use crate::{backend, command, utils};
use crate::backend::backend::Backend;
use crate::init::initialize_backend;
use once_cell::sync::OnceCell;
use lazy_static::lazy_static;
use size::Size;
use crate::utils::{get_totp, reply_group_simple, reply_group_simple_str, sec_to_duration_dhms};
use crate::backend::backend::StickerUploadDomain;

pub struct BotEventHandler {
    backend: OnceCell<Backend>,
    backend_init_msg: RwLock<String>,
    backend_init_called: RwLock<bool>,

    last_totp_code: RwLock<String>,
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

            "purge_db" => {
                let totp = get_totp();

                if totp.is_err() {
                    let err_msg = format!("创建TOTP生成器失败：{}", totp.unwrap_err().to_string());
                    tracing::log::warn!("{}", err_msg);
                    return Ok(reply_group_simple(&ctx, &message, err_msg).await?);
                }

                let totp_code = totp.unwrap().generate_current();
                if totp_code.is_err() {
                    let err_msg = format!("生成TOTP Challenge失败：{}", totp_code.unwrap_err().to_string());
                    tracing::log::warn!("{}", err_msg);
                    return Ok(reply_group_simple(&ctx, &message, err_msg).await?);
                }

                if params.len() < 4 ||
                    params[0].to_lowercase() != "i'm" ||
                    params[1].to_lowercase() != "absolutely" ||
                    params[2].to_lowercase() != "sure" ||
                    params[3] != totp_code.unwrap() {

                    tracing::log::warn!("有用户尝试执行数据库重建，但被阻止了。命令原文：{}", message.content.as_ref().unwrap());
                    reply_group_simple(&ctx, &message, String::from("无法执行：未输入正确的TOTP Challenge或者解除安全保护指令。")).await
                } else if params[3] == *self.last_totp_code.read().unwrap() {

                    reply_group_simple(&ctx, &message, String::from("无法执行：此TOTP Challenge刚刚成功使用过。")).await
                } else {
                    *self.last_totp_code.write().unwrap() = params[3].clone();

                    reply_group_simple(&ctx, &message, String::from("执行了数据库重建。之前的所有数据已经备份，数据库已恢复至初始状态。")).await
                }
            }

            "/su" => 'su: {
                // Sticker Upload -
                // /su [.u/.user/.g/.group] tag [..tags] WithOneImageAttachment
                self.backend_init().await?;

                // Ensure exactly one image attachment
                if message.attachments.len() != 1 {
                    break 'su reply_group_simple(&ctx, &message, "需要在消息中附带1个图片才可使用。".into()).await;
                }

                // Get the corresponding OpenID for the specified domain
                let domain = if params.len() >= 2 && params[0].starts_with(".") {
                    let ret = match &params[0][1..] {
                        "g" | "group" => StickerUploadDomain::Group,
                        "u" | "user" | _ => StickerUploadDomain::User,
                    };
                    params.remove(0); // Get rid of the domain specifier
                    ret
                } else { StickerUploadDomain::User };
                let domain_openid = match domain {
                    StickerUploadDomain::Group => if message.group_openid.is_none() {
                        break 'su reply_group_simple(&ctx, &message, "内部错误：message.group_openid为None".into()).await
                    } else {
                        &message.group_openid.as_ref().unwrap()
                    },
                    StickerUploadDomain::User => if message.author.is_none() {
                        break 'su reply_group_simple(&ctx, &message, "内部错误：message.author为None".into()).await
                    } else if message.author.as_ref().unwrap().member_openid.is_none() {
                        break 'su reply_group_simple(&ctx, &message, "内部错误：message.author.member_openid为None".into()).await
                    } else {
                        &message.author.as_ref().unwrap().member_openid.as_ref().unwrap()
                    }
                };

                // Join all specified tags with space
                let tags = params.join(" ");

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

                if let Err(e) = self.backend().handle_sticker_upload(
                    atta.url.as_ref().unwrap(), filename, domain_openid, tags
                ).await {
                    reply_group_simple(&ctx, &message, format!("添加表情错误：{}", e)).await
                } else {
                    reply_group_simple(&ctx, &message, "成功添加了一个表情。".into()).await
                }
            }

            _ => reply_group_simple(&ctx, &message, format!("未知的指令：{}", params[0])).await
        }?;

        Ok(())
    }
}
