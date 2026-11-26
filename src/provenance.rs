use crate::id::{BlobId, ChangeId, EntityId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use ulid::Ulid;

/// Unique identifier for a provenance activity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ActivityId(pub Ulid);

impl ActivityId {
    /// Generates a new random activity identifier.
    pub fn new() -> Self {
        Self(Ulid::generate())
    }
}

impl Default for ActivityId {
    fn default() -> Self {
        Self::new()
    }
}

/// Execution status of a provenance activity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActivityStatus {
    /// Activity started execution.
    Started,
    /// Activity completed successfully.
    Completed,
    /// Activity failed with an error message.
    Failed(String),
}

/// Target resource referenced in provenance tracking.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ProvenanceTarget {
    /// Target is an entity.
    Entity(EntityId),
    /// Target is a binary large object.
    Blob(BlobId),
    /// Target is a change record.
    Change(ChangeId),
}

/// Record of an execution activity for provenance tracking.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Activity {
    /// Unique identifier of this activity.
    pub id: ActivityId,
    /// Name of the process or workflow.
    pub process_name: String,
    /// Version of the process or tool.
    pub version: String,
    /// Timestamp when the activity started.
    pub started_at: DateTime<Utc>,
    /// Optional timestamp when the activity completed.
    pub completed_at: Option<DateTime<Utc>>,
    /// Input resources consumed by this activity.
    pub inputs: Vec<ProvenanceTarget>,
    /// Output resources produced by this activity.
    pub outputs: Vec<ProvenanceTarget>,
    /// Configuration parameters used during execution.
    pub configuration: BTreeMap<String, String>,
    /// Current status of the activity.
    pub status: ActivityStatus,
}

impl Activity {
    /// Creates a new activity with the specified process name and version.
    pub fn new(process_name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            id: ActivityId::new(),
            process_name: process_name.into(),
            version: version.into(),
            started_at: Utc::now(),
            completed_at: None,
            inputs: Vec::new(),
            outputs: Vec::new(),
            configuration: BTreeMap::new(),
            status: ActivityStatus::Started,
        }
    }

    /// Adds an input resource to the activity.
    pub fn add_input(&mut self, input: ProvenanceTarget) {
        self.inputs.push(input);
    }

    /// Adds an output resource to the activity.
    pub fn add_output(&mut self, output: ProvenanceTarget) {
        self.outputs.push(output);
    }

    /// Sets a configuration key-value pair.
    pub fn set_config(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.configuration.insert(key.into(), value.into());
    }

    /// Marks the activity as completed.
    pub fn complete(&mut self) {
        self.completed_at = Some(Utc::now());
        self.status = ActivityStatus::Completed;
    }

    /// Marks the activity as failed with an error message.
    pub fn fail(&mut self, error: impl Into<String>) {
        self.completed_at = Some(Utc::now());
        self.status = ActivityStatus::Failed(error.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_activity_lifecycle_and_provenance() {
        let mut act = Activity::new("ocr_pipeline", "1.2.0");
        let input_blob = BlobId::new();
        let output_entity = EntityId::new();

        act.add_input(ProvenanceTarget::Blob(input_blob));
        act.add_output(ProvenanceTarget::Entity(output_entity));
        act.set_config("language", "pl");
        act.complete();

        assert_eq!(act.status, ActivityStatus::Completed);
        assert_eq!(act.inputs.len(), 1);
        assert_eq!(act.outputs.len(), 1);

        let json = serde_json::to_string(&act).unwrap();
        let deserialized: Activity = serde_json::from_str(&json).unwrap();
        assert_eq!(act, deserialized);
    }
}
