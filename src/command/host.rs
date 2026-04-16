use std::sync::Arc;
use size::Size;
use tokio::sync::Mutex;
use crate::backend::backend::Backend;
use crate::command::BotCommand;
use crate::error_glue::CrustaneError;
use crate::utils::{reply_group_simple, sec_to_duration_dhms};
use crate::utils::wrappers::CommonMessage;

pub struct Host;

#[async_trait::async_trait]
impl BotCommand for Host {
    fn cmd_prefix(&self) -> &'static str {
        "host"
    }

    async fn trigger(&self, backend: Arc<Mutex<Backend>>, msg: &CommonMessage) -> Result<(), CrustaneError> {
        let sys = sysinfo::System::new_all();
        msg.reply_plain(
            format!(
                "\n主机名：{}\n执行用户：{}\nRAM：{}/{}\n主机已运行时长：{}",
                sysinfo::System::host_name()
                    .map_or(String::from("<无法获得主机名>"), |s| s),
                whoami::username(),
                Size::from_bytes(sys.used_memory()),
                Size::from_bytes(sys.total_memory()),
                sec_to_duration_dhms(sysinfo::System::uptime())
            ),
            None
        ).await
    }
}
