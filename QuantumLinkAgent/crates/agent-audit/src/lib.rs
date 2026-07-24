//! Append-only JSONL audit log with a tamper-evident hash chain.

use qlink_agent_contracts::AuditEvent;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};

pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn append(&self, mut event: AuditEvent) -> Result<AuditEvent, String> {
        let prior = self.read_all()?;
        event.previous_event_hash = prior.last().map(|item| item.event_hash.clone());
        event.event_hash = hash_event(&event)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|error| error.to_string())?;
        serde_json::to_writer(&mut file, &event).map_err(|error| error.to_string())?;
        file.write_all(b"\n").map_err(|error| error.to_string())?;
        file.sync_data().map_err(|error| error.to_string())?;
        Ok(event)
    }

    pub fn read_all(&self) -> Result<Vec<AuditEvent>, String> {
        if !self.path.exists() {
            return Ok(vec![]);
        }
        let file = File::open(&self.path).map_err(|error| error.to_string())?;
        BufReader::new(file)
            .lines()
            .map(|line| {
                let line = line.map_err(|error| error.to_string())?;
                serde_json::from_str(&line).map_err(|error| error.to_string())
            })
            .collect()
    }

    pub fn verify(&self) -> Result<bool, String> {
        let mut previous = None;
        for event in self.read_all()? {
            if event.previous_event_hash != previous || hash_event(&event)? != event.event_hash {
                return Ok(false);
            }
            previous = Some(event.event_hash);
        }
        Ok(true)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn hash_event(event: &AuditEvent) -> Result<String, String> {
    let mut unhashed = event.clone();
    unhashed.event_hash.clear();
    let bytes = serde_json::to_vec(&unhashed).map_err(|error| error.to_string())?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
