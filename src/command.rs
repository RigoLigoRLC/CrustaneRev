use std::env;
use std::time::Duration;
use botrs::{Context, GroupMessage, Timestamp};
use chrono::{DateTime, TimeDelta, Utc};
use size::Size;
use totp_rs::{Algorithm, Secret};
use tracing::log::warn;
use crate::utils::{get_totp, reply_group_simple, reply_group_simple_str, sec_to_duration_dhms};

static mut LAST_TOTP_CODE: String = String::new();

pub(crate) async fn dispatch_call_from_group(ctx: Context, message: GroupMessage, params: Vec<String>) -> Result<(), String> {
    if params.is_empty() {
        return Ok(reply_group_simple_str(&ctx, &message, "请输入命令").await?);
    }

    match params[0].as_str() {
        "ping" => reply_group_simple(
            &ctx, &message,
            format!(
                "Pong! \nPing 请求耗费了 {} ms 到达 Bot 端。",
                (Utc::now() - message.timestamp.ok_or("时间戳为None")?).num_milliseconds()
            )
        ),

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
            )
        },

        "purge_db" => {
            let totp = get_totp();

            if totp.is_err() {
                let err_msg = format!("创建TOTP生成器失败：{}", totp.unwrap_err().to_string());
                warn!("{}", err_msg);
                return Ok(reply_group_simple(&ctx, &message, err_msg).await?);
            }

            let totp_code = totp.unwrap().generate_current();
            if totp_code.is_err() {
                let err_msg = format!("生成TOTP Challenge失败：{}", totp_code.unwrap_err().to_string());
                warn!("{}", err_msg);
                return Ok(reply_group_simple(&ctx, &message, err_msg).await?);
            }

            if params.len() < 5 ||
                params[1].to_lowercase() != "i'm" ||
                params[2].to_lowercase() != "absolutely" ||
                params[3].to_lowercase() != "sure" ||
                params[4] != totp_code.unwrap() {

                warn!("有用户尝试执行数据库重建，但被阻止了。命令原文：{}", message.content.as_ref().unwrap());
                reply_group_simple(&ctx, &message, String::from("无法执行：未输入正确的TOTP Challenge或者解除安全保护指令。"))
            } else if unsafe { params[4] == LAST_TOTP_CODE } {

                reply_group_simple(&ctx, &message, String::from("无法执行：此TOTP Challenge刚刚成功使用过。"))
            } else {

                unsafe { LAST_TOTP_CODE = params[4].clone() };

                reply_group_simple(&ctx, &message, String::from("执行了数据库重建。之前的所有数据已经备份，数据库已恢复至初始状态。"))
            }
        }

        _ => reply_group_simple(&ctx, &message, format!("未知的指令：{}", params[0]))
    }.await?;

    Ok(())
}
