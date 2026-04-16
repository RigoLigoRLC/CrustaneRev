use std::collections::HashMap;
use crate::backend::backend::StickerDomain;
use crate::backend::backend::{Backend, StickerLiberatorOperation, StickerRecipient};
use crate::error_glue::CrustaneError;
use crate::init::initialize_backend;
use crate::utils::wrappers::CommonMessage;
use crate::utils::{
    get_group_openid_group_msg, get_sender_openid_group_msg, get_totp, reply_c2c_simple_str,
    reply_group_simple, reply_group_simple_str, reply_group_with_media, sec_to_duration_dhms,
};
use crate::{backend, command, utils};
use async_trait::async_trait;
use botrs::{C2CMessage, Context, EventHandler, GroupMessage, GroupMessageParams, Media, Ready};
use chrono::format::parse;
use chrono::{DateTime, Utc};
use futures::StreamExt;
use once_cell::sync::OnceCell;
use regex::Regex;
use serde_json::Value;
use size::Size;
use sqlx::query;
use std::ops::Deref;
use std::sync::{Arc, RwLock};
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use crate::command::BotCommand;

/// Context for each user.
///
/// This is where stateful commands store stuff. Like. You send one thing, the command expects you
/// send an additional piece, and the "expectation" is expressed by setting a hook in this context,
/// and by the next time the user sends a message, the message is routed to this command first; and
/// if the user invokes another command, an optionally registered abort hook can also be
/// automatically invoked.
struct BotPerUserContext {}

pub struct BotEventHandler {
    registered_commands: HashMap<String, Box<dyn BotCommand + Send + Sync>>,

    backend: OnceCell<Arc<Mutex<Backend>>>,
    backend_init_msg: RwLock<String>,
    backend_init_called: RwLock<bool>,

    facetype_garbage_regex: Regex,
}

impl BotEventHandler {
    fn register_command(&mut self, command: Box<dyn BotCommand + Send + Sync>) {
        self.registered_commands.insert(command.cmd_prefix().to_string(), command);
    }

    async fn unified_msg_create_dispatch(
        &self,
        mut msg: CommonMessage,
    ) -> Result<(), CrustaneError> {
        if let Err(e) = msg.parse_params_from_content_trimmed() {
            return msg
                .reply_plain(format!("字符串参数解析出错：\n{}", e), None)
                .await;
        }

        // TODO: C2C messages
        // TODO: Idle message redirections
        // TODO: Feature switches for C2C and Group messages

        if msg.params()?.len() == 0 {
            return msg.reply_plain("当前不支持不包含文本的消息".into(), None).await;
        }

        let command_prefix = &msg.params()?[0];
        if self.registered_commands.contains_key(command_prefix) {
            self.registered_commands
                .get(command_prefix)
                .ok_or::<CrustaneError>(format!("无法到达的代码路径(TOCTOU?)：“{}”命令无法找到", command_prefix).into())?
                .trigger(self.backend(), &msg)
                .await
        } else {
            msg.reply_plain(format!("命令“{}”无法找到", command_prefix), None).await
        }
    }
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
        if let Err(e) = self
            .unified_msg_create_dispatch(CommonMessage::from_group_message(ctx, message))
            .await
        {
            warn!("群消息分发时出错：{}", e);
        }
    }

    async fn c2c_message_create(&self, ctx: Context, message: C2CMessage) {
        if let Err(e) = self
            .unified_msg_create_dispatch(CommonMessage::from_c2c_message(ctx, message))
            .await
        {
            warn!("C2C消息分发时出错：{}", e);
        }
    }
}

impl Default for BotEventHandler {
    fn default() -> Self {
        let mut ret = Self {
            registered_commands: HashMap::new(),
            backend: OnceCell::new(),
            backend_init_msg: RwLock::default(),
            backend_init_called: RwLock::default(),
            facetype_garbage_regex: Regex::new(r#"<faceType=.+?>"#).unwrap(),
        };

        // FIXME: This is really poorly designed, should find a better place and a better way to register commands
        ret.register_command(Box::new(command::ping::Ping));
        ret.register_command(Box::new(command::host::Host));
        ret.register_command(Box::new(command::slash_su::SlashSu::default()));
        ret.register_command(Box::new(command::slash_ss::SlashSs));
        ret.register_command(Box::new(command::slash_si::SlashSi));

        ret
    }
}

impl BotEventHandler {
    /// Must call backend_init when you needed backend.
    /// Panicking in this function is your fault.
    fn backend(&self) -> Arc<Mutex<Backend>> {
        self.backend.get().unwrap().clone()
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
                    self.backend.get_or_init(|| Arc::new(Mutex::new(backend)));
                    Ok(())
                }
                Err(e) => {
                    *self.backend_init_msg.write().unwrap() = e;
                    Err(self.backend_init_msg.read().unwrap().deref().clone())
                }
            }
        }
    }


    // async fn dispatch_call_from_group<'a>(
    //     &self,
    //     ctx: Context,
    //     message: &'a GroupMessage,
    //     mut params: Vec<&'a str>,
    // ) -> Result<(), String> {
    //     if params.is_empty() {
    //         return Ok(reply_group_simple_str(&ctx, &message, "请输入命令").await?);
    //     }
    //
    //     match params.remove(0) {
    //         "su" => 'su: {
    //             // su - verify superuser identity
    //             // su exit/<totp challenge>
    //             if params.len() != 1 {
    //                 break 'su reply_group_simple_str(
    //                     &ctx,
    //                     &message,
    //                     "必须携带一个参数：exit，或者TOTP Challenge。",
    //                 )
    //                 .await;
    //             }
    //
    //             if params[0] == "exit" {
    //                 (*self.superuser_openid.write().unwrap()).clear();
    //                 reply_group_simple_str(&ctx, &message, "您已退出超级用户状态。").await
    //             } else {
    //                 match self.verify_totp_challenge(params[0]) {
    //                     Ok(_) => {
    //                         (*self.superuser_openid.write().unwrap())
    //                             .push_str(get_sender_openid_group_msg(&message)?);
    //                         reply_group_simple_str(&ctx, &message, "您已成功验证超级用户权限。此状态可自动在进行特权操作后维持30分钟。").await
    //                     }
    //                     Err(e) => reply_group_simple(&ctx, &message, e).await,
    //                 }
    //             }
    //         }
    //
    //         "purge_db" => 'purge_db: {
    //             match self.verify_superuser_privilege_group(&message) {
    //                 Ok(_) => reply_group_simple_str(&ctx, &message, "还没实现").await,
    //                 Err(e) => {
    //                     break 'purge_db reply_group_simple(
    //                         &ctx,
    //                         &message,
    //                         format!("您不是验证的超级用户（{}），无法执行。", e),
    //                     )
    //                     .await;
    //                 }
    //             }
    //         }
    //
    //         "liberator" => 'liberator: {
    //             // liberator - become/quit as a liberator.
    //             // liberator become/quit <TOTP Challenge>
    //             let usage = || {
    //                 reply_group_simple_str(&ctx, &message, "liberator become/quit <TOTP Challenge>")
    //             };
    //             if params.len() > 2 || params.is_empty() {
    //                 break 'liberator usage().await;
    //             }
    //
    //             let openid = get_sender_openid_group_msg(&message)?;
    //             let verification = match self
    //                 .backend()
    //                 .sticker_liberator_ops(openid, StickerLiberatorOperation::Verify)
    //                 .await
    //             {
    //                 Ok(verification) => verification,
    //                 Err(e) => break 'liberator Err(e),
    //             };
    //
    //             match params[0] {
    //                 "become" => match self.verify_totp_challenge(params[1]) {
    //                     Ok(()) => {
    //                         if verification != 0 {
    //                             reply_group_simple_str(&ctx, &message, "您已经是解放者了。").await
    //                         } else {
    //                             match self.backend().sticker_liberator_ops(openid, StickerLiberatorOperation::Add).await {
    //                                     Ok(_) => reply_group_simple_str(&ctx, &message, "您成为了解放者；您今后上传的表情包所有人都将可搜索。\n如您想将以往的表情包都变为所有人可搜索的状态，请使用“liberate”命令。").await,
    //                                     Err(e) => reply_group_simple(&ctx, &message, format!("无法成为解放者：{}", e)).await,
    //                                 }
    //                         }
    //                     }
    //                     Err(e) => {
    //                         reply_group_simple(
    //                             &ctx,
    //                             &message,
    //                             format!("无法成为解放者：TOTP验证失败：{}", e),
    //                         )
    //                         .await
    //                     }
    //                 },
    //                 "quit" => {
    //                     if verification != 0 {
    //                         match self
    //                             .backend()
    //                             .sticker_liberator_ops(openid, StickerLiberatorOperation::Remove)
    //                             .await
    //                         {
    //                             Ok(_) => {
    //                                 reply_group_simple_str(&ctx, &message, "您已不再是解放者。")
    //                                     .await
    //                             }
    //                             Err(e) => {
    //                                 reply_group_simple(
    //                                     &ctx,
    //                                     &message,
    //                                     format!("无法成为解放者：{}", e),
    //                                 )
    //                                 .await
    //                             }
    //                         }
    //                     } else {
    //                         reply_group_simple_str(&ctx, &message, "您已经是解放者了。").await
    //                     }
    //                 }
    //                 _ => break 'liberator usage().await,
    //             }
    //         }
    //
    //         "liberate" => 'liberate: {
    //             // liberate - liberate all of the user's stickers. The user must have already
    //             // become a liberator or be verified as superuser.
    //             // A liberator can liberate his own stickers. The superuser can liberate any sticker
    //             // with an ID.
    //             // liberate [id]
    //             // If no ID is provided, the current verified user's all stickers will be liberated.
    //             let openid = get_sender_openid_group_msg(&message)?;
    //             let mut auth_err_msg: String = String::new();
    //             let is_liberator = match self
    //                 .backend()
    //                 .sticker_liberator_ops(openid, StickerLiberatorOperation::Verify)
    //                 .await
    //             {
    //                 Ok(n) => n != 0,
    //                 Err(e) => {
    //                     let e = e.to_string();
    //                     auth_err_msg.push_str(e.as_str());
    //                     false
    //                 }
    //             };
    //             let is_superuser = self.verify_superuser_privilege_group(&message);
    //             if is_superuser.is_err() && !is_liberator {
    //                 break 'liberate reply_group_simple(
    //                     &ctx,
    //                     &message,
    //                     format!(
    //                         "您无权公有化您的表情包。只有超级用户或者经过TOTP验证的解放者有权操作（{}）。{}{}",
    //                         is_superuser.unwrap_err(),
    //                         if auth_err_msg.is_empty() { "" } else { "\n\n" },
    //                         auth_err_msg
    //                     )
    //                 ).await;
    //             }
    //
    //             if params.len() == 0 {
    //                 let openid = get_sender_openid_group_msg(&message)?;
    //                 match self.backend().sticker_liberate_all(openid).await {
    //                     Ok(count) => {
    //                         reply_group_simple(
    //                             &ctx,
    //                             &message,
    //                             format!("公有化了{}个表情包。", count),
    //                         )
    //                         .await
    //                     }
    //                     Err(e) => reply_group_simple(&ctx, &message, e).await,
    //                 }
    //             } else if params.len() == 1 {
    //                 let id = match params[0].parse::<i64>() {
    //                     Ok(id) => id,
    //                     Err(e) => {
    //                         break 'liberate reply_group_simple(
    //                             &ctx,
    //                             &message,
    //                             format!("参数指定的ID无法转换为i64：{}", e),
    //                         )
    //                         .await;
    //                     }
    //                 };
    //
    //                 if !match self.backend().sticker_exists(id).await {
    //                     Ok(x) => x,
    //                     Err(e) => break 'liberate reply_group_simple(&ctx, &message, e).await,
    //                 } {
    //                     break 'liberate reply_group_simple(
    //                         &ctx,
    //                         &message,
    //                         format!("不存在ID={}的表情包。", id),
    //                     )
    //                     .await;
    //                 }
    //                 match self
    //                     .backend()
    //                     .sticker_liberate_one(is_superuser.is_ok(), openid, id)
    //                     .await
    //                 {
    //                     Ok(()) => {
    //                         reply_group_simple(
    //                             &ctx,
    //                             &message,
    //                             format!("公有化了ID={}的表情包。", id),
    //                         )
    //                         .await
    //                     }
    //                     Err(e) => reply_group_simple(&ctx, &message, e).await,
    //                 }
    //             } else {
    //                 break 'liberate reply_group_simple_str(&ctx, &message, "liberate [表情ID]")
    //                     .await;
    //             }
    //         }
    //
    //         "/si" => '_si: {
    //             // Sticker Inspect -
    //             // /si <sticker_id> [optional_operation  [optional_parameters]]
    //             let help = || {
    //                 return reply_group_simple_str(
    //                     &ctx,
    //                     &message,
    //                     concat!(
    //                         "/si - Sticker Inspection 表情图修改\n",
    //                         "  /si <ID> [可选操作 [可选参数 ...]]\n",
    //                         "  当未提供操作时，将显示此表情的详细信息；\n",
    //                         "可用的操作有：\n",
    //                         "  set-tag <新Tag>\n",
    //                         "当您要对某个表情进行操作时，您必须是上传者本人或者超级用户。",
    //                     ),
    //                 );
    //             };
    //             if params.len() == 0 {
    //                 break '_si help().await;
    //             }
    //
    //             let id = match params.remove(0).parse::<i64>() {
    //                 Ok(id) => id,
    //                 Err(e) => {
    //                     break '_si reply_group_simple_str(
    //                         &ctx,
    //                         &message,
    //                         "您输入的ID无法解析为整数。",
    //                     )
    //                     .await;
    //                 }
    //             };
    //
    //             if params.len() == 0 {
    //                 break '_si match self.backend().sticker_inspect_simple(id).await {
    //                     Ok(result) => match result {
    //                         Some(result) => {
    //                             reply_group_simple(
    //                                 &ctx,
    //                                 &message,
    //                                 format!(
    //                                     concat!(
    //                                         "ID={}\n",
    //                                         "Tags=\"{}\"\n",
    //                                         "上传于 {}\n\n",
    //                                         "所属域ID={}\n",
    //                                         "上传者ID={}\n",
    //                                         "view_level={}",
    //                                     ),
    //                                     id,
    //                                     result.tags,
    //                                     result.added_date,
    //                                     result.domain_openid,
    //                                     result.uploader_openid,
    //                                     result.view_level
    //                                 ),
    //                             )
    //                             .await
    //                         }
    //                         None => {
    //                             reply_group_simple_str(
    //                                 &ctx,
    //                                 &message,
    //                                 "您输入的ID未匹配任何表情包。",
    //                             )
    //                             .await
    //                         }
    //                     },
    //                     Err(e) => reply_group_simple(&ctx, &message, e.into()).await,
    //                 };
    //             }
    //
    //             let sender_openid = match get_sender_openid_group_msg(&message) {
    //                 Ok(result) => result,
    //                 Err(e) => {
    //                     break '_si reply_group_simple(
    //                         &ctx,
    //                         &message,
    //                         format!("获取发送者OpenID失败：{}", e),
    //                     )
    //                     .await;
    //                 }
    //             };
    //
    //             let uploader = match self.backend().sticker_uploader_openid_query(id).await {
    //                 Ok(uploader) => uploader,
    //                 Err(e) => {
    //                     break '_si reply_group_simple(
    //                         &ctx,
    //                         &message,
    //                         format!("查询表情包上传者失败：{}", e),
    //                     )
    //                     .await;
    //                 }
    //             };
    //
    //             let is_superuser = self.verify_superuser_privilege_group(&message);
    //
    //             if !uploader.eq(sender_openid) && is_superuser.is_err() {
    //                 break '_si reply_group_simple(
    //                     &ctx,
    //                     &message,
    //                     format!(
    //                         "您不是表情包的上传者或者超级用户（{}），无法操作这个表情包。",
    //                         is_superuser.unwrap_err()
    //                     ),
    //                 )
    //                 .await;
    //             }
    //
    //             match params[0] {
    //                 "set-tag" => {
    //                     if params.len() != 2 {
    //                         break '_si help().await;
    //                     }
    //                     match self.backend().sticker_set_tags(id, params[1]).await {
    //                         Ok(_) => {
    //                             reply_group_simple_str(
    //                                 &ctx,
    //                                 &message,
    //                                 "成功修改了指定表情包的标签。",
    //                             )
    //                             .await
    //                         }
    //                         Err(e) => reply_group_simple(&ctx, &message, e.into()).await,
    //                     }
    //                 }
    //                 _ => help().await,
    //             }
    //         }
    //
    //         "ssi" => 'ssi: {
    //             if params.len() == 0 {
    //                 break 'ssi reply_group_simple_str(&ctx, &message, "必须指定搜索关键字。")
    //                     .await;
    //             }
    //
    //             match self
    //                 .backend()
    //                 .sticker_id_query_domainless(params.join(" "))
    //                 .await
    //             {
    //                 Ok(result) => {
    //                     let result = result
    //                         .iter()
    //                         .map(|it| format!("ID={}", it))
    //                         .collect::<Vec<String>>()
    //                         .join("\n");
    //                     info!("查询结果：\n{}", result);
    //                     reply_group_simple(&ctx, &message, result).await
    //                 }
    //                 Err(e) => {
    //                     error!("数据库操作失败\n{}", e);
    //                     reply_group_simple(&ctx, &message, e).await
    //                 }
    //             }
    //         }
    //
    //         unknown => reply_group_simple(&ctx, &message, format!("未知的指令：{}", unknown)).await,
    //     }?;
    //
    //     Ok(())
    // }
}
