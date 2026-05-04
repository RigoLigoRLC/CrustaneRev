use std::collections::HashMap;
use crate::backend::backend::{Backend, StickerLiberatorOperation, StickerRecipient};
use crate::error_glue::CrustaneError;
use crate::init::initialize_backend;
use crate::utils::wrappers::CommonMessage;
use crate::utils::{
    get_group_openid_group_msg, get_sender_openid_group_msg, get_totp, reply_c2c_simple_str,
    reply_group_simple, reply_group_simple_str, reply_group_with_media, sec_to_duration_dhms,
};
use crate::{backend, command, utils};
use botrs::{C2CMessage, Context, EventHandler, GroupMessage, GroupMessageParams, Media, Ready};
use chrono::{DateTime, Utc};
use once_cell::sync::OnceCell;
use regex::Regex;
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
        ret.register_command(Box::new(command::su::Su));

        ret.register_command(Box::new(command::slash_su::SlashSu::default()));
        ret.register_command(Box::new(command::slash_ss::SlashSs));
        ret.register_command(Box::new(command::slash_si::SlashSi));
        ret.register_command(Box::new(command::ssi::Ssi));
        ret.register_command(Box::new(command::liberate::Liberate));
        ret.register_command(Box::new(command::liberator::Liberator));

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
    //
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
    //

    //
    //         unknown => reply_group_simple(&ctx, &message, format!("未知的指令：{}", unknown)).await,
    //     }?;
    //
    //     Ok(())
    // }
}
