use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct PasswordItem {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub password: crate::Secret,
    #[serde(skip_serializing_if = "skip_security_questions")]
    pub security_questions: Option<Vec<SecurityQuestion>>,
    #[serde(flatten)]
    pub additional: HashMap<String, serde_json::Value>,
}

impl crate::KeyringItem for PasswordItem {
    fn mimetype() -> &'static str {
        "application/prs.thanatos.keyring.password+json"
    }

    fn serialize(&self) -> Result<Vec<u8>, anyhow::Error> {
        Ok(serde_json::to_vec(self)?)
    }

    fn deserialize(data: &[u8]) -> Result<Self, anyhow::Error> {
        Ok(serde_json::from_slice(data)?)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SecurityQuestion {
    #[serde(rename = "q")]
    pub question: String,
    #[serde(rename = "a")]
    pub answer: String,
}

fn skip_security_questions(security_qs: &Option<Vec<SecurityQuestion>>) -> bool {
    match security_qs.as_ref() {
        Some(qs) => qs.is_empty(),
        None => true,
    }
}
