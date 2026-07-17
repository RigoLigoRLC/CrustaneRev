use std::sync::Arc;

use itertools::Itertools;
use tokio::sync::Mutex;

use crate::{backend::backend::Backend, command::BotCommand, error_glue::CrustaneError, utils::wrappers::CommonMessage};


pub struct Sql;

#[async_trait::async_trait]
impl BotCommand for Sql {
    fn cmd_prefix(&self) -> &'static str {
        "sql"
    }

    async fn trigger(&self, backend: Arc<Mutex<Backend>>, msg: &CommonMessage) -> Result<(), CrustaneError> {
        if let Err(e) =  backend.lock().await.superuser_state().verify_superuser_privilege_group(msg.msg.author()?.member_or_openid()?) {
            return msg.reply_plain("只有超级用户才能执行任意SQL命令".into(), None).await;
        }

        let params = msg.params()?;

        if params.len() == 1 {
            return msg.reply_plain("用法：sql [SQL查询]\n\n只有超级用户可以使用。".into(), None).await;
        }

        let mut params = params.iter();
        params.next();

        let query = params.join(" ");
        match backend.lock().await.db_query(query.as_str()).await {
            Ok(x) => msg.reply_plain(x, None),
            Err(e) => msg.reply_plain(format!("执行SQL查询时出错：{}", e), None),
        }.await
    }
}

