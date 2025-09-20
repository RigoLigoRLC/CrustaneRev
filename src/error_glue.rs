use std::env::VarError;
use std::fmt::{Display, Formatter};
use botrs::BotError;

#[derive(Debug)]
pub(crate) enum CrustaneError {
    BotrsError(BotError),
    StrError(String),
}

impl Display for CrustaneError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl From<BotError> for CrustaneError {
    fn from(e: BotError) -> Self {
        CrustaneError::BotrsError(e)
    }
}

impl From<String> for CrustaneError {
    fn from(e: String) -> Self {
        CrustaneError::StrError(e)
    }
}

impl From<&str> for CrustaneError {
    fn from(e: &str) -> Self {
        CrustaneError::StrError(e.to_string())
    }
}

impl From<VarError> for CrustaneError {
    fn from(e: VarError) -> Self {
        e.to_string().into()
    }
}

impl From<totp_rs::TotpUrlError> for CrustaneError {
    fn from(e: totp_rs::TotpUrlError) -> Self {
        e.to_string().into()
    }
}

impl From<CrustaneError> for String {
    fn from(e: CrustaneError) -> String {
        match e {
            CrustaneError::BotrsError(ref e) => e.to_string(),
            CrustaneError::StrError(ref e) => e.to_string(),
        }
    }
}

impl From<reqwest::Error> for CrustaneError {
    fn from(e: reqwest::Error) -> Self {
        format!("reqwest Error: {}", e).into()
    }
}

impl From<std::io::Error> for CrustaneError {
    fn from(e: std::io::Error) -> Self {
        format!("IO Error: {}", e).into()
    }
}
