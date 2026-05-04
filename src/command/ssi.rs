use std::sync::Arc;
use itertools::Itertools;
use tokio::sync::Mutex;
use tracing::{error, info};
use crate::backend::backend::Backend;
use crate::command::BotCommand;
use crate::error_glue::CrustaneError;
use crate::utils::wrappers::CommonMessage;

pub struct Ssi;

#[async_trait::async_trait]
impl BotCommand for Ssi {
    fn cmd_prefix(&self) -> &'static str {
        "ssi"
    }

    async fn trigger(&self, backend: Arc<Mutex<Backend>>, msg: &CommonMessage) -> Result<(), CrustaneError> {
        let params = msg.params()?;
        if params.len() == 1 {
            return msg.reply_plain("必须指定搜索关键字。".into(), None).await;
        }

        match backend.lock().await.sticker_id_query_domainless(params.iter().skip(1).join(" ")).await {
            Ok(result) => {
                let result = result
                    .iter()
                    .map(|it| format!("ID={}", it))
                    .collect::<Vec<String>>()
                    .join("\n");
                info!("查询结果：\n{}", result);
                msg.reply_plain(result, None).await
            }
            Err(e) => {
                error!("数据库操作失败\n{}", e);
                msg.reply_plain(e, None).await
            }
        }
    }
}
