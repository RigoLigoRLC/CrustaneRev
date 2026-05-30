
use std::ops::{Index, Range};
use botrs::{C2CMessage, C2CMessageParams, C2CMessageUser, Context, GroupMessage, GroupMessageParams, GroupMessageUser, Media, MessageAttachment, Reference};
use chrono::{DateTime, Utc};
use crate::error_glue::CrustaneError;
use crate::utils;

pub trait WrappedUser {
    /// Returns id field.
    fn openid(&self) -> Result<&str, CrustaneError>;

    /// Returns union_openid.
    fn union_openid(&self) -> Result<&str, CrustaneError>;

    /// Returns member_openid. Only usable when representing a GroupMessage.
    fn member_openid(&self) -> Result<&str, CrustaneError>;

    /// Returns member_openid if available, if not, returns openid.
    fn member_or_openid(&self) -> Result<&str, CrustaneError>;
}

impl WrappedUser for GroupMessageUser {
    fn openid(&self) -> Result<&str, CrustaneError> {
        self.id
            .as_ref()
            .map(|x| x.as_str())
            .ok_or("user的id为空".into())
    }

    fn union_openid(&self) -> Result<&str, CrustaneError> {
        self.union_openid
            .as_ref()
            .map(|x| x.as_str())
            .ok_or("user的union_openid为空".into())
    }

    fn member_openid(&self) -> Result<&str, CrustaneError> {
        self.member_openid
            .as_ref()
            .map(|x| x.as_str())
            .ok_or("user的member_openid为空".into())
    }

    fn member_or_openid(&self) -> Result<&str, CrustaneError> {
        self.member_openid
            .as_ref()
            .or(self.id.as_ref())
            .map(|x| x.as_str())
            .ok_or("user的id与member_openid均为空".into())
    }
}

impl WrappedUser for C2CMessageUser {
    fn openid(&self) -> Result<&str, CrustaneError> {
        self.id
            .as_ref()
            .map(|x| x.as_str())
            .ok_or("user的id为空".into())
    }

    fn union_openid(&self) -> Result<&str, CrustaneError> {
        self.union_openid
            .as_ref()
            .map(|x| x.as_str())
            .ok_or("user的union_openid为空".into())
    }

    fn member_openid(&self) -> Result<&str, CrustaneError> {
        Err("尝试对C2C消息获取member_openid".into())
    }

    fn member_or_openid(&self) -> Result<&str, CrustaneError> {
        self.id
            .as_ref()
            .map(|x| x.as_str())
            .ok_or("C2C消息：user的id为空".into())
    }
}

#[derive(Copy, Clone)]
pub enum WrappedMessageType {
    GroupMessage,
    C2CMessage,
}

impl Into<i32> for WrappedMessageType {
    fn into(self) -> i32 {
        match self {
            WrappedMessageType::GroupMessage => 0,
            WrappedMessageType::C2CMessage => 1,
        }
    }
}

pub trait WrappedMessage {
    /// Get the underlying (Group/C2C/...) type of message.
    fn msg_type(&self) -> WrappedMessageType;

    /// Get message ID as String.
    fn id(&self) -> Result<&str, CrustaneError>;

    /// Get message content as String.
    fn content(&self) -> Result<&str, CrustaneError>;

    /// Get attachments user message has sent with.
    fn attachments(&self) -> Result<&Vec<MessageAttachment>, CrustaneError>;

    /// Get message timestamp as DateTime.
    fn timestamp(&self) -> Result<DateTime<Utc>, CrustaneError>;

    /// Get author object.
    fn author(&self) -> Result<&(dyn WrappedUser + Send + Sync), CrustaneError>;

    /// Get the OpenID of message source. Group OpenID for GroupMessage, User OpenID for C2CMessage.
    fn source_openid(&self) -> Result<&str, CrustaneError>;

    /// Get the quoted message, if available. If the value is Err it means we failed to parse the
    /// quoted message. If the value is Ok(None), it means no message is quoted.
    fn quoted_msg(&self) -> Result<Option<Box<dyn WrappedMessage + Send + Sync>>, CrustaneError>;
}

impl WrappedMessage for GroupMessage {
    fn msg_type(&self) -> WrappedMessageType {
        WrappedMessageType::GroupMessage
    }

    fn id(&self) -> Result<&str, CrustaneError> {
        self.id
            .as_ref()
            .map(|x| x.as_str())
            .ok_or("message的id为空".into())
    }

    fn content(&self) -> Result<&str, CrustaneError> {
        self.content
            .as_ref()
            .map(|x| x.as_str())
            .ok_or("message的content为空".into())
    }

    fn attachments(&self) -> Result<&Vec<MessageAttachment>, CrustaneError> {
        Ok(&self.attachments)
    }

    fn timestamp(&self) -> Result<DateTime<Utc>, CrustaneError> {
        // Timestamp parsing was removed from botrs in some time between 0.2.6 and 0.12.2.
        // Timestamp would look like such: "2026-05-26T23:13:34+08:00"
        self.timestamp
            .as_deref()
            .ok_or("message的timestamp为空".into())
            .and_then(|x| {
                DateTime::parse_from_rfc3339(x)
                    .map_err(|x| x.to_string().into())
                    .map(|x| x.with_timezone(&Utc))
            })
    }

    fn author(&self) -> Result<&(dyn WrappedUser + Send + Sync), CrustaneError> {
        self.author
            .as_ref()
            .map(|x| x as &(dyn WrappedUser + Send + Sync))
            .ok_or("message的author为空".into())
    }

    fn source_openid(&self) -> Result<&str, CrustaneError> {
        self.group_openid
            .as_ref()
            .map(|x| x.as_str())
            .ok_or("message的group_openid为空".into())
    }

    fn quoted_msg(&self) -> Result<Option<Box<dyn WrappedMessage + Send + Sync>>, CrustaneError> {
        let msg_elements = self.msg_elements.as_ref().map(|x| x.as_array()).flatten();
        if let Some(msg_elements) = msg_elements && msg_elements.len() >= 1 {
            let parsed_quote = serde_json::from_value::<GroupMessage>(msg_elements[0].clone());
            if let Ok(msg) = parsed_quote {
                Ok(Some(Box::new(msg)))
            } else {
                Err(format!("无法解析引用的消息：{}", parsed_quote.unwrap_err()).into())
            }
        } else {
            Ok(None)
        }
    }
}

impl WrappedMessage for C2CMessage {
    fn msg_type(&self) -> WrappedMessageType {
        WrappedMessageType::C2CMessage
    }

    fn id(&self) -> Result<&str, CrustaneError> {
        self.id
            .as_ref()
            .map(|x| x.as_str())
            .ok_or("message的id为空".into())
    }

    fn content(&self) -> Result<&str, CrustaneError> {
        self.content
            .as_ref()
            .map(|x| x.as_str())
            .ok_or("message的content为空".into())
    }

    fn attachments(&self) -> Result<&Vec<MessageAttachment>, CrustaneError> {
        Ok(&self.attachments)
    }

    fn timestamp(&self) -> Result<DateTime<Utc>, CrustaneError> {
        // Timestamp parsing was removed from botrs in some time between 0.2.6 and 0.12.2.
        // Timestamp would look like such: "2026-05-26T23:13:34+08:00"
        self.timestamp
            .as_deref()
            .ok_or("message的timestamp为空".into())
            .and_then(|x| {
                DateTime::parse_from_rfc3339(x)
                    .map_err(|x| x.to_string().into())
                    .map(|x| x.with_timezone(&Utc))
            })
    }

    fn author(&self) -> Result<&(dyn WrappedUser + Send + Sync), CrustaneError> {
        self.author
            .as_ref()
            .map(|x| x as &(dyn WrappedUser + Send + Sync))
            .ok_or("message的author为空".into())
    }

    fn source_openid(&self) -> Result<&str, CrustaneError> {
        self.author()?.openid()
    }

    fn quoted_msg(&self) -> Result<Option<Box<dyn WrappedMessage + Send + Sync>>, CrustaneError> {
        let msg_elements = self.msg_elements.as_ref().map(|x| x.as_array()).flatten();
        if let Some(msg_elements) = msg_elements && msg_elements.len() >= 1 {
            let parsed_quote = serde_json::from_value::<C2CMessage>(msg_elements[0].clone());
            if let Ok(msg) = parsed_quote {
                Ok(Some(Box::new(msg)))
            } else {
                Err(format!("无法解析引用的消息：{}", parsed_quote.unwrap_err()).into())
            }
        } else {
            Ok(None)
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct MessageParamSpans {
    spans: Vec<Range<usize>>,
}

impl MessageParamSpans {
    fn update_from_trimmed_content(&mut self, content: &str) -> Result<(), CrustaneError> {
        let trimmed = content.trim();
        let trim_start = content.len() - content.trim_start().len();
        let spans = utils::msg_content_split_spans(trimmed)?;
        self.spans = spans
            .into_iter()
            .map(|span| (span.start + trim_start)..(span.end + trim_start))
            .collect();
        Ok(())
    }
}

pub struct MessageParams<'a> {
    content: &'a str,
    spans: &'a [Range<usize>],
}

impl<'a> MessageParams<'a> {
    pub fn len(&self) -> usize {
        self.spans.len()
    }

    pub fn is_empty(&self) -> bool {
        self.spans.is_empty()
    }

    pub fn get(&self, index: usize) -> Option<&'a str> {
        self.spans
            .get(index)
            .map(|span| &self.content[span.start..span.end])
    }

    pub fn iter(&self) -> impl Iterator<Item = &'a str> + 'a {
        self.spans
            .iter()
            .map(|span| &self.content[span.start..span.end])
    }

    pub fn to_vec(&self) -> Vec<&'a str> {
        self.iter().collect()
    }
}

impl<'a> Index<usize> for MessageParams<'a> {
    type Output = str;

    fn index(&self, index: usize) -> &Self::Output {
        let span = &self.spans[index];
        &self.content[span.start..span.end]
    }
}

/// The "Common" message, which includes botrs Context object (API key, etc.) and a wrapper for
/// all sorts of supported messages (Group, C2C, ...).
///
/// The wrapper provides basically a unified interface to all underlying message types.
///
/// Including botrs Context type makes it easier to generally "do things" like replying.
pub struct CommonMessage {
    pub context: Context,
    pub msg: Box<dyn WrappedMessage + Send + Sync>,
    param_spans: MessageParamSpans,
}

impl CommonMessage {
    pub fn from_group_message(context: Context, msg: GroupMessage) -> CommonMessage {
        CommonMessage {
            context,
            msg: Box::from(msg),
            param_spans: MessageParamSpans::default(),
        }
    }

    pub fn from_c2c_message(context: Context, msg: C2CMessage) -> CommonMessage {
        CommonMessage {
            context,
            msg: Box::from(msg),
            param_spans: MessageParamSpans::default(),
        }
    }

    pub fn parse_params_from_content_trimmed(&mut self) -> Result<(), CrustaneError> {
        let content = self.msg.content()?;
        self.param_spans.update_from_trimmed_content(content)
    }

    pub fn params(&self) -> Result<MessageParams<'_>, CrustaneError> {
        Ok(MessageParams {
            content: self.msg.content()?,
            spans: &self.param_spans.spans,
        })
    }

    pub async fn reply_plain(
        &self,
        content: String,
        media: Option<Media>,
    ) -> Result<(), CrustaneError> {
        self.reply_plain_with_seq(content, media, None).await
    }

    pub async fn reply_plain_with_seq(
        &self,
        content: String,
        media: Option<Media>,
        seq_counter: Option<&mut SeqCounter>,
    ) -> Result<(), CrustaneError> {
        let msg_id_str = self.msg.id()?.to_string();
        match self.msg.msg_type() {
            WrappedMessageType::C2CMessage => {
                let params = C2CMessageParams {
                    msg_type: if media.is_some() { 7 } else { 0 },
                    content: Some(content),
                    msg_id: Some(msg_id_str.clone()),
                    message_reference: Some(Reference {
                        message_id: Some(msg_id_str),
                        ignore_get_message_error: Some(true),
                    }),
                    media,
                    msg_seq: seq_counter.map(|x| { x.count += 1; x.count }),
                    ..Default::default()
                };

                self.context
                    .api
                    .post_c2c_message_with_params(&self.context.token, self.msg.source_openid()?, params)
                    .await
                    .map(|_| ())
                    .map_err(|e| e.into())
            }

            WrappedMessageType::GroupMessage => {
                let params = GroupMessageParams {
                    msg_type: if media.is_some() { 7 } else { 0 },
                    content: Some(content),
                    msg_id: Some(msg_id_str.clone()),
                    message_reference: Some(Reference {
                        message_id: Some(msg_id_str),
                        ignore_get_message_error: Some(true),
                    }),
                    media,
                    msg_seq: seq_counter.map(|x| { x.count += 1; x.count }),
                    ..Default::default()
                };

                self.context
                    .api
                    .post_group_message_with_params(&self.context.token, self.msg.source_openid()?, params)
                    .await
                    .map(|_| ())
                    .map_err(|e| e.into())
            }
        }
    }
}

pub struct SeqCounter {
    pub count: u32,
}

impl SeqCounter {
    pub fn new() -> SeqCounter {
        SeqCounter { count: 1 }
    }
}

#[cfg(test)]
mod tests {
    use super::{MessageParamSpans, MessageParams};

    #[test]
    fn message_params_index_returns_str_slice() {
        let content = "ping one two";
        let spans = vec![0..4, 5..8, 9..12];
        let params = MessageParams {
            content,
            spans: &spans,
        };

        assert_eq!(&params[0], "ping");
        assert_eq!(&params[1], "one");
        assert_eq!(&params[2], "two");
    }

    #[test]
    fn message_param_spans_keep_trimmed_offset() {
        let content = "  ping one two  ";
        let mut spans = MessageParamSpans::default();
        spans.update_from_trimmed_content(content).unwrap();
        let params = MessageParams {
            content,
            spans: &spans.spans,
        };

        assert_eq!(&params[0], "ping");
        assert_eq!(&params[1], "one");
        assert_eq!(&params[2], "two");
    }
}
