//! Relation types and hypergraph relation definitions.

use crate::id::{EntityId, RelationId};
use crate::value::{PropertyName, PropertyValue};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;

/// Represents errors that can occur when creating or modifying relations.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RelationError {
    /// Relation must contain at least one member.
    #[error("Relation must have at least one member")]
    EmptyMembers,
}

/// Represents an entity participant and its role in a relation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelationMember {
    /// Identifier of the participant entity.
    pub entity_id: EntityId,
    /// Role of the participant entity within the relation.
    pub role: String,
}

impl RelationMember {
    /// Creates a new relation member with an entity identifier and role name.
    pub fn new(entity_id: EntityId, role: impl Into<String>) -> Self {
        Self {
            entity_id,
            role: role.into(),
        }
    }
}

/// Represents a hypergraph relation connecting one or more entities with arbitrary roles.
#[derive(Debug, Clone, PartialEq)]
pub struct Relation {
    /// Unique identifier of the relation.
    pub id: RelationId,
    /// Type name of the relation.
    pub relation_type: String,
    /// List of entity participants and their roles.
    pub members: Vec<RelationMember>,
    /// Map of property names to property values.
    pub properties: BTreeMap<PropertyName, PropertyValue>,
}

#[derive(Serialize, Deserialize)]
struct RelationWire {
    id: RelationId,
    relation_type: String,
    #[serde(default)]
    members: Vec<RelationMember>,
    #[serde(default)]
    source: Option<EntityId>,
    #[serde(default)]
    target: Option<EntityId>,
    #[serde(default)]
    properties: BTreeMap<PropertyName, PropertyValue>,
}

impl Serialize for Relation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let wire = RelationWire {
            id: self.id,
            relation_type: self.relation_type.clone(),
            members: self.members.clone(),
            source: self.source(),
            target: self.target(),
            properties: self.properties.clone(),
        };
        wire.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Relation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = RelationWire::deserialize(deserializer)?;
        let mut members = wire.members;
        if members.is_empty() {
            if let Some(src) = wire.source {
                members.push(RelationMember::new(src, "source"));
            }
            if let Some(tgt) = wire.target {
                members.push(RelationMember::new(tgt, "target"));
            }
        }

        if members.is_empty() {
            return Err(serde::de::Error::custom(
                "Relation must contain at least one member",
            ));
        }

        Ok(Relation {
            id: wire.id,
            relation_type: wire.relation_type,
            members,
            properties: wire.properties,
        })
    }
}

impl Relation {
    /// Creates a multimember relation with at least one member.
    pub fn new(
        id: RelationId,
        relation_type: impl Into<String>,
        members: Vec<RelationMember>,
    ) -> Result<Self, RelationError> {
        if members.is_empty() {
            return Err(RelationError::EmptyMembers);
        }
        Ok(Self {
            id,
            relation_type: relation_type.into(),
            members,
            properties: BTreeMap::new(),
        })
    }

    /// Convenience constructor for binary source/target relations.
    pub fn new_binary(
        id: RelationId,
        relation_type: impl Into<String>,
        source: EntityId,
        target: EntityId,
    ) -> Self {
        Self {
            id,
            relation_type: relation_type.into(),
            members: vec![
                RelationMember::new(source, "source"),
                RelationMember::new(target, "target"),
            ],
            properties: BTreeMap::new(),
        }
    }

    /// Helper to get the first member with role "source", if present.
    pub fn source(&self) -> Option<EntityId> {
        self.members
            .iter()
            .find(|m| m.role == "source")
            .map(|m| m.entity_id)
    }

    /// Helper to get the first member with role "target", if present.
    pub fn target(&self) -> Option<EntityId> {
        self.members
            .iter()
            .find(|m| m.role == "target")
            .map(|m| m.entity_id)
    }

    /// Returns all members having a specific role.
    pub fn members_by_role(&self, role: &str) -> Vec<&RelationMember> {
        self.members.iter().filter(|m| m.role == role).collect()
    }

    /// Checks if a given entity participates in this relation.
    pub fn has_member(&self, entity_id: &EntityId) -> bool {
        self.members.iter().any(|m| m.entity_id == *entity_id)
    }

    /// Sets or replaces the value of a property on the relation.
    pub fn set_property(&mut self, name: impl Into<PropertyName>, value: impl Into<PropertyValue>) {
        self.properties.insert(name.into(), value.into());
    }

    /// Retrieves a reference to a property value if present.
    pub fn get_property(&self, name: &PropertyName) -> Option<&PropertyValue> {
        self.properties.get(name)
    }

    /// Removes a property by name and returns its previous value if present.
    pub fn remove_property(&mut self, name: &PropertyName) -> Option<PropertyValue> {
        self.properties.remove(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relation_creation_and_properties() {
        let e1 = EntityId::new();
        let e2 = EntityId::new();
        let mut rel = Relation::new_binary(RelationId::new(), "created_by", e1, e2);

        let role_prop: PropertyName = "role".into();
        rel.set_property(role_prop.clone(), "author");

        assert_eq!(rel.source(), Some(e1));
        assert_eq!(rel.target(), Some(e2));
        assert!(rel.has_member(&e1));
        assert!(rel.has_member(&e2));
        assert_eq!(
            rel.get_property(&role_prop),
            Some(&PropertyValue::from("author"))
        );

        let json = serde_json::to_string(&rel).unwrap();
        let deserialized: Relation = serde_json::from_str(&json).unwrap();
        assert_eq!(rel, deserialized);
    }

    #[test]
    fn test_multimember_relation_lifecycle() {
        let e1 = EntityId::new();
        let e2 = EntityId::new();
        let e3 = EntityId::new();

        let members = vec![
            RelationMember::new(e1, "supervisor"),
            RelationMember::new(e2, "contributor"),
            RelationMember::new(e3, "contributor"),
        ];

        let rel = Relation::new(RelationId::new(), "collaborates_on", members).unwrap();
        assert_eq!(rel.members.len(), 3);
        assert_eq!(rel.members_by_role("contributor").len(), 2);
        assert_eq!(rel.members_by_role("supervisor").len(), 1);
        assert!(rel.has_member(&e3));

        // Rejection when empty members passed
        assert_eq!(
            Relation::new(RelationId::new(), "collaborates_on", vec![]),
            Err(RelationError::EmptyMembers)
        );
    }

    #[test]
    fn test_legacy_source_target_json_migration() {
        let e1 = EntityId::new();
        let e2 = EntityId::new();
        let rel_id = RelationId::new();

        let legacy_json = serde_json::json!({
            "id": rel_id,
            "relation_type": "parent_of",
            "source": e1,
            "target": e2,
            "properties": {}
        })
        .to_string();

        let rel: Relation = serde_json::from_str(&legacy_json).unwrap();
        assert_eq!(rel.id, rel_id);
        assert_eq!(rel.members.len(), 2);
        assert_eq!(rel.members[0].entity_id, e1);
        assert_eq!(rel.members[0].role, "source");
        assert_eq!(rel.members[1].entity_id, e2);
        assert_eq!(rel.members[1].role, "target");
        assert_eq!(rel.source(), Some(e1));
        assert_eq!(rel.target(), Some(e2));
    }
}
