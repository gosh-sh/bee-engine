// copied from https://github.com/tvmlabs/tvm-sdk/blob/main/tvm_vm/src/executor/zk_stuff/zk_login.rs
use std::fmt;
use std::fmt::Formatter;
use std::str::FromStr;
use std::sync::LazyLock;

use regex::Regex;

use super::error::ZkCryptoError;

static RE_AWS_TENANT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"AwsTenant-region:(?P<region>[^.]+)-tenant_id:(?P<tenant_id>[^/]+)")
        .expect("AWS tenant regex is invalid — this is a compile-time constant")
});

static RE_AWS_ISS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"https://cognito-idp\.(?P<region>[^.]+)\.amazonaws\.com/(?P<tenant_id>[^/]+)")
        .expect("AWS ISS regex is invalid — this is a compile-time constant")
});

/// Supported OIDC providers.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum OIDCProvider {
    /// See https://accounts.google.com/.well-known/openid-configuration
    Google,
    /// See https://id.twitch.tv/oauth2/.well-known/openid-configuration
    Twitch,
    /// See https://www.facebook.com/.well-known/openid-configuration/
    Facebook,
    /// See https://kauth.kakao.com/.well-known/openid-configuration
    Kakao,
    /// See https://appleid.apple.com/.well-known/openid-configuration
    Apple,
    /// See https://slack.com/.well-known/openid-configuration
    Slack,
    /// See https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration
    Microsoft,
    /// Example: https://cognito-idp.us-east-1.amazonaws.com/us-east-1_LPSLCkC3A/.well-known/jwks.json
    AwsTenant((String, String)),
    /// https://accounts.karrier.one/.well-known/openid-configuration
    KarrierOne,
    /// https://accounts.credenza3.com/openid-configuration
    Credenza3,
    Gosh,
}

impl FromStr for OIDCProvider {
    type Err = ZkCryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "google" => Ok(Self::Google),
            "gosh" => Ok(Self::Gosh),
            "twitch" => Ok(Self::Twitch),
            "facebook" => Ok(Self::Facebook),
            "kakao" => Ok(Self::Kakao),
            "apple" => Ok(Self::Apple),
            "slack" => Ok(Self::Slack),
            "microsoft" => Ok(Self::Microsoft),
            "karrierOne" => Ok(Self::KarrierOne),
            "credenza3" => Ok(Self::Credenza3),
            _ => {
                if let Some(captures) = RE_AWS_TENANT.captures(s) {
                    let region = captures.name("region").unwrap().as_str();
                    let tenant_id = captures.name("tenant_id").unwrap().as_str();
                    Ok(Self::AwsTenant((region.to_owned(), tenant_id.to_owned())))
                } else {
                    Err(ZkCryptoError::InvalidInput)
                }
            }
        }
    }
}

impl fmt::Display for OIDCProvider {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Google => write!(f, "google"),
            Self::Gosh => write!(f, "gosh"),
            Self::Twitch => write!(f, "twitch"),
            Self::Facebook => write!(f, "facebook"),
            Self::Kakao => write!(f, "kakao"),
            Self::Apple => write!(f, "apple"),
            Self::Slack => write!(f, "slack"),
            Self::Microsoft => write!(f, "microsoft"),
            Self::KarrierOne => write!(f, "karrierOne"),
            Self::Credenza3 => write!(f, "credenza3"),
            Self::AwsTenant((region, tenant_id)) => {
                write!(f, "AwsTenant-region:{}-tenant_id:{}", region, tenant_id)
            }
        }
    }
}

impl OIDCProvider {
    /// Returns the OIDCProvider for the given iss string.
    pub fn from_iss(iss: &str) -> Result<Self, ZkCryptoError> {
        match iss {
            "https://accounts.google.com" => Ok(Self::Google),
            "https://oauth.gosh.sh" => Ok(Self::Gosh),
            "https://id.twitch.tv/oauth2" => Ok(Self::Twitch),
            "https://www.facebook.com" => Ok(Self::Facebook),
            "https://kauth.kakao.com" => Ok(Self::Kakao),
            "https://appleid.apple.com" => Ok(Self::Apple),
            "https://slack.com" => Ok(Self::Slack),
            "https://accounts.karrier.one/" => Ok(Self::KarrierOne),
            "https://accounts.credenza3.com" => Ok(Self::Credenza3),
            iss if match_micrsoft_iss_substring(iss) => Ok(Self::Microsoft),
            _ => match parse_aws_iss_substring(iss) {
                Ok((region, tenant_id)) => Ok(Self::AwsTenant((region, tenant_id))),
                Err(_) => Err(ZkCryptoError::InvalidInput),
            },
        }
    }
}

/// Check if the iss string is formatted as Microsoft's pattern.
fn match_micrsoft_iss_substring(iss: &str) -> bool {
    iss.starts_with("https://login.microsoftonline.com/") && iss.ends_with("/v2.0")
}

/// Parse the region and tenant_id from the iss string for AWS.
fn parse_aws_iss_substring(url: &str) -> Result<(String, String), ZkCryptoError> {
    if let Some(captures) = RE_AWS_ISS.captures(url) {
        let region = captures.name("region").unwrap().as_str().to_owned();
        let tenant_id = captures.name("tenant_id").unwrap().as_str().to_owned();
        Ok((region, tenant_id))
    } else {
        Err(ZkCryptoError::InvalidInput)
    }
}
