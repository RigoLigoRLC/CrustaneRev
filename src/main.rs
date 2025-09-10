mod command;
mod utils;
mod error_glue;
mod init;

use std::env::args;
use botrs::{Client, Context, EventHandler, Intents, Token, Message, GroupMessage, GroupMessageParams};
use botrs::models::gateway::Ready;
use tracing::{info, warn};
use crate::utils::get_totp;

struct MyBot;

#[async_trait::async_trait]
impl EventHandler for MyBot {
    async fn ready(&self, _ctx: Context, ready: Ready) {
        info!("Bot {} is ready!", ready.user.username);
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

            if let Err(e) = command::dispatch_call_from_group(ctx, message, params).await {
                warn!("群消息分发时出错：{}", e);
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    for (i, s) in args().enumerate() {
        if i == 1 && s == "totp_qr" {
            let qr = get_totp().unwrap().get_url();
            println!("This is the administrator TOTP QR Code. Please scan!");
            qr2term::print_qr(&qr)?;
        }
    }

    // 初始化日志
    tracing_subscriber::fmt::init();

    // 创建令牌
    let token = Token::from_env().unwrap();

    // 设置意图
    let intents = Intents::default();

    // 创建客户端
    let mut client = Client::new(token, intents, MyBot, true)?;

    // 启动机器人
    client.start().await?;

    Ok(())
}