use std::sync::Arc;
use chrono::Utc;
use tokio::sync::Mutex;
use crate::backend::backend::Backend;
use crate::command::BotCommand;
use crate::error_glue::CrustaneError;
use crate::utils::wrappers::CommonMessage;

pub struct Ping;

#[async_trait::async_trait]
impl BotCommand for Ping {
    fn cmd_prefix(&self) -> &'static str {
        "ping"
    }

    async fn trigger(&self, backend: Arc<Mutex<Backend>>, msg: &CommonMessage) -> Result<(), CrustaneError> {
        msg.reply_plain(
            format!(
                "Pong! \nPing 请求耗费了 {} ms 到达 Bot 端。",
                (Utc::now() - msg.msg.timestamp()?).num_milliseconds()
            ),
            None
        ).await
    }
}
