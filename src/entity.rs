//! Entity data structures and manipulation methods.

use crate::id::EntityId;
use crate::value::{PropertyName, PropertyValue};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Represents an entity record that has a unique identifier and key-value properties.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entity {
    /// Unique identifier of the entity.
    pub id: EntityId,
    /// Optional schema or domain type name of the entity.
    pub entity_type: Option<String>,
    /// Map of property names to property values.
    pub properties: BTreeMap<PropertyName, PropertyValue>,
}

impl Entity {
    /// Creates a new entity with the specified identifier and no type.
    pub fn new(id: EntityId) -> Self {
        Self {
            id,
            entity_type: None,
            properties: BTreeMap::new(),
        }
    }

    /// Creates a new entity with the specified identifier and type name.
    pub fn with_type(id: EntityId, entity_type: impl Into<String>) -> Self {
        Self {
            id,
            entity_type: Some(entity_type.into()),
            properties: BTreeMap::new(),
        }
    }

    /// Sets or replaces the value of a property.
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
    fn test_entity_creation_and_properties() {
        let mut entity = Entity::with_type(EntityId::new(), "contact");
        assert_eq!(entity.entity_type.as_deref(), Some("contact"));

        let prop_name: PropertyName = "name".into();
        entity.set_property(prop_name.clone(), "Jan Kowalski");

        assert_eq!(
            entity.get_property(&prop_name),
            Some(&PropertyValue::from("Jan Kowalski"))
        );

        let json = serde_json::to_string(&entity).unwrap();
        let deserialized: Entity = serde_json::from_str(&json).unwrap();
        assert_eq!(entity, deserialized);
    }
}
