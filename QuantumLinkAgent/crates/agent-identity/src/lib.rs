//! Pluggable workload identity. Dytallix is optional, never an admission dependency by accident.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityStatus {
    Active,
    Missing,
    Expired,
    Revoked,
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityAssertion {
    pub subject: String,
    pub status: IdentityStatus,
    pub provider: String,
    pub provenance: String,
    pub expires_at_unix: Option<u64>,
}

pub trait IdentityProvider: Send + Sync {
    fn name(&self) -> &str;
    fn resolve(&self, subject: &str, now_unix: u64) -> IdentityAssertion;
    fn verify(&self, assertion: &IdentityAssertion, now_unix: u64) -> bool;
    fn revoke(&mut self, subject: &str) -> Result<(), String>;
    fn refresh(&mut self, subject: &str, now_unix: u64) -> IdentityAssertion;
}

#[derive(Default)]
pub struct LocalIdentityProvider {
    records: BTreeMap<String, IdentityStatus>,
}

impl LocalIdentityProvider {
    pub fn register(&mut self, subject: impl Into<String>) {
        self.records.insert(subject.into(), IdentityStatus::Active);
    }
}

impl IdentityProvider for LocalIdentityProvider {
    fn name(&self) -> &str {
        "local"
    }

    fn resolve(&self, subject: &str, _now_unix: u64) -> IdentityAssertion {
        IdentityAssertion {
            subject: subject.into(),
            status: self
                .records
                .get(subject)
                .cloned()
                .unwrap_or(IdentityStatus::Missing),
            provider: self.name().into(),
            provenance: "local-workload-registry".into(),
            expires_at_unix: None,
        }
    }

    fn verify(&self, assertion: &IdentityAssertion, now_unix: u64) -> bool {
        assertion.provider == self.name()
            && assertion.status == IdentityStatus::Active
            && assertion
                .expires_at_unix
                .is_none_or(|expiry| now_unix < expiry)
    }

    fn revoke(&mut self, subject: &str) -> Result<(), String> {
        match self.records.get_mut(subject) {
            Some(status) => {
                *status = IdentityStatus::Revoked;
                Ok(())
            }
            None => Err("identity not found".into()),
        }
    }

    fn refresh(&mut self, subject: &str, now_unix: u64) -> IdentityAssertion {
        self.resolve(subject, now_unix)
    }
}

pub struct DytallixIdentityProvider<F>
where
    F: Fn(&str) -> Result<(IdentityStatus, Option<u64>), String> + Send + Sync,
{
    lookup: F,
}

impl<F> DytallixIdentityProvider<F>
where
    F: Fn(&str) -> Result<(IdentityStatus, Option<u64>), String> + Send + Sync,
{
    pub fn new(lookup: F) -> Self {
        Self { lookup }
    }
}

impl<F> IdentityProvider for DytallixIdentityProvider<F>
where
    F: Fn(&str) -> Result<(IdentityStatus, Option<u64>), String> + Send + Sync,
{
    fn name(&self) -> &str {
        "dytallix"
    }

    fn resolve(&self, subject: &str, _now_unix: u64) -> IdentityAssertion {
        let (status, expiry) =
            (self.lookup)(subject).unwrap_or((IdentityStatus::Unavailable, None));
        IdentityAssertion {
            subject: subject.into(),
            status,
            provider: self.name().into(),
            provenance: "dytallix-registry".into(),
            expires_at_unix: expiry,
        }
    }

    fn verify(&self, assertion: &IdentityAssertion, now_unix: u64) -> bool {
        assertion.provider == self.name()
            && assertion.status == IdentityStatus::Active
            && assertion
                .expires_at_unix
                .is_none_or(|expiry| now_unix < expiry)
    }

    fn revoke(&mut self, _subject: &str) -> Result<(), String> {
        Err("Dytallix revocation requires the registry authority".into())
    }

    fn refresh(&mut self, subject: &str, now_unix: u64) -> IdentityAssertion {
        self.resolve(subject, now_unix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn local_and_dytallix_are_independent_providers() {
        let mut local = LocalIdentityProvider::default();
        local.register("agent-a");
        assert!(local.verify(&local.resolve("agent-a", 1), 1));
        let chain = DytallixIdentityProvider::new(|_| Err("offline".into()));
        assert_eq!(
            chain.resolve("agent-a", 1).status,
            IdentityStatus::Unavailable
        );
    }
}
