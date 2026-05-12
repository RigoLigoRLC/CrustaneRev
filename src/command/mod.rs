pub mod ping;
pub mod host;
pub mod slash_su;
pub mod slash_ss;
pub mod slash_si;
pub mod su;
pub mod liberate;
pub mod liberator;
pub mod ssi;
pub(crate) mod slash_sr;

use std::sync::Arc;
use tokio::sync::Mutex;
use crate::backend::backend::Backend;
use crate::error_glue::CrustaneError;
use crate::utils::wrappers::CommonMessage;

#[async_trait::async_trait]
pub trait BotCommand {
    /// The very first part of the command. If a slash is required to invoke a command, it shall
    /// also be included in the return value of this function.
    fn cmd_prefix(&self) -> &'static str;

    /// This function will be called by the event handler when user invokes a command (sent the bot
    /// with a message whose first space-delimited part matches the `cmd_prefix`.
    ///
    /// You generally should reply the user with something in this function to indicate how the
    /// command has been going.
    ///
    /// Assuming a command is stateless (which is to say, each individual command invocation are
    /// independent of each other invocation - a previous invocation doesn't affect invocations that
    /// comes later), there's not much to take care of. But NEVER AWAIT ANYTHING THAT TAKES TOO LONG
    /// inside `trigger` because the underlying Bot event loop will be blocked.
    async fn trigger(&self, backend: Arc<Mutex<Backend>>, msg: &CommonMessage) -> Result<(), CrustaneError>;
}
