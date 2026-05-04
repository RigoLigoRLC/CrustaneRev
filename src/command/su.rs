use std::sync::Arc;
use tokio::sync::Mutex;
use crate::backend::backend::Backend;
use crate::command::BotCommand;
use crate::error_glue::CrustaneError;
use crate::utils::wrappers::CommonMessage;

pub struct Su;

#[async_trait::async_trait]
impl BotCommand for Su {
    fn cmd_prefix(&self) -> &'static str {
        "su"
    }

    async fn trigger(&self, backend: Arc<Mutex<Backend>>, msg: &CommonMessage) -> Result<(), CrustaneError> {
        // su - verify superuser identity
        // su exit/<totp challenge>
        let params = msg.params()?;
        if params.len() != 2 {
            return msg.reply_plain(
                "必须携带一个参数：exit，或者TOTP Challenge。".into(),
                None,
            ).await;
        }

        let backend = backend.lock().await;
        let su_state = backend.superuser_state();
        if &params[1] == "exit" {
            // (*self.superuser_openid.write().unwrap()).clear();
            if let Err(e) = su_state.superuser_exit(msg.msg.author()?.member_or_openid()?) {
                msg.reply_plain(e.to_string(), None).await
            } else {
                msg.reply_plain("您已退出超级用户状态。".into(), None).await
            }
        } else {
            match su_state.verify_totp_challenge(&params[1]) {
                Ok(_) => {
                    su_state.superuser_enter(msg.msg.author()?.member_or_openid()?);
                    msg.reply_plain("您已成功验证超级用户权限。此状态可自动在进行特权操作后维持30分钟。".into(), None).await
                }
                Err(e) => msg.reply_plain(e.to_string(), None).await,
            }
        }
    }
}
