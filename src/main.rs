mod command;
mod utils;
mod error_glue;
mod init;
mod backend;
mod botevent;

use std::env::args;
use std::process::exit;
use botrs::{Client, Intents, Token};
use botevent::BotEventHandler;
use crate::utils::get_totp;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    for (i, s) in args().enumerate() {
        if i == 1 && s == "totp_qr" {
            let qr = get_totp().unwrap().get_url();
            println!("This is the administrator TOTP QR Code. Please scan!");
            qr2term::print_qr(&qr)?;
        }

        if i == 1 && s == "ota_test" {
            println!("Boop! Executable is alive.");
            exit(0);
        }
    }

    // 初始化日志
    tracing_subscriber::fmt::init();

    // 给SQLite添加simple分词插件
    libsimple::enable_auto_extension().expect("libsimple cannot load");

    // 创建令牌
    let token = Token::from_env().unwrap();

    // 设置意图
    let intents = Intents::default();

    // 创建客户端
    let mut client = Client::new(token, intents, BotEventHandler::default(), true)?;

    // 启动机器人
    client.start().await?;

    Ok(())
}