use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Permission flags for dataset access control.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Permission {
    /// Permission to read entities.
    ReadEntities,
    /// Permission to create, update, or delete entities.
    WriteEntities,
    /// Permission to read binary large objects.
    ReadBlobs,
    /// Permission to write binary large objects.
    WriteBlobs,
    /// Permission to read change history and the DAG.
    ReadHistory,
    /// Permission to append changes to the history DAG.
    WriteHistory,
    /// Permission to manage application permissions.
    ManagePermissions,
    /// Permission to read cryptographic keys.
    ReadCryptoKeys,
    /// Permission to create or rotate cryptographic keys.
    ManageCryptoKeys,
}

/// Registration information and permissions for an application.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppRegistration {
    /// Unique identifier of the application.
    pub app_id: String,
    /// Human-readable name of the application.
    pub name: String,
    /// Set of granted permissions.
    pub permissions: BTreeSet<Permission>,
    /// Indicates if access for this application is revoked.
    pub revoked: bool,
}

impl AppRegistration {
    /// Creates a new application registration.
    pub fn new(app_id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            app_id: app_id.into(),
            name: name.into(),
            permissions: BTreeSet::new(),
            revoked: false,
        }
    }

    /// Grants a permission to the application.
    pub fn grant(&mut self, perm: Permission) {
        self.permissions.insert(perm);
    }

    /// Revokes a permission from the application.
    pub fn revoke_permission(&mut self, perm: &Permission) {
        self.permissions.remove(perm);
    }

    /// Revokes all access for the application.
    pub fn revoke_app(&mut self) {
        self.revoked = true;
    }
}

/// Errors related to security and access control.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SecurityError {
    /// Application identifier was not found.
    #[error("App not found: {0}")]
    AppNotFound(String),
    /// Application access has been revoked.
    #[error("App access has been revoked: {0}")]
    AppRevoked(String),
    /// Application lacks the required permission.
    #[error("Permission denied for app {app_id}: requires {permission:?}")]
    PermissionDenied {
        /// Identifier of the application.
        app_id: String,
        /// Missing permission.
        permission: Permission,
    },
}

/// Controls application permissions and trusted devices.
#[derive(Debug, Clone, Default)]
pub struct AccessController {
    trusted_devices: BTreeSet<String>,
    apps: BTreeMap<String, AppRegistration>,
}

impl AccessController {
    /// Creates a new access controller instance.
    pub fn new() -> Self {
        Self {
            trusted_devices: BTreeSet::new(),
            apps: BTreeMap::new(),
        }
    }

    /// Adds a device identifier to the set of trusted devices.
    pub fn add_trusted_device(&mut self, device_id: impl Into<String>) {
        self.trusted_devices.insert(device_id.into());
    }

    /// Checks if a device identifier is trusted.
    pub fn is_device_trusted(&self, device_id: &str) -> bool {
        self.trusted_devices.contains(device_id)
    }

    /// Registers an application with the controller.
    pub fn register_app(&mut self, app: AppRegistration) {
        self.apps.insert(app.app_id.clone(), app);
    }

    /// Checks if an application has the specified permission.
    pub fn check_permission(&self, app_id: &str, perm: &Permission) -> Result<(), SecurityError> {
        let app = self
            .apps
            .get(app_id)
            .ok_or_else(|| SecurityError::AppNotFound(app_id.to_string()))?;

        if app.revoked {
            return Err(SecurityError::AppRevoked(app_id.to_string()));
        }

        if !app.permissions.contains(perm) {
            return Err(SecurityError::PermissionDenied {
                app_id: app_id.to_string(),
                permission: perm.clone(),
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_access_controller_permissions_and_revocation() {
        let mut ac = AccessController::new();
        ac.add_trusted_device("laptop-dev");
        assert!(ac.is_device_trusted("laptop-dev"));
        assert!(!ac.is_device_trusted("unknown-phone"));

        let mut app = AppRegistration::new("app:notes", "Notes Client");
        app.grant(Permission::ReadEntities);
        ac.register_app(app);

        assert!(
            ac.check_permission("app:notes", &Permission::ReadEntities)
                .is_ok()
        );
        assert!(matches!(
            ac.check_permission("app:notes", &Permission::WriteEntities),
            Err(SecurityError::PermissionDenied { .. })
        ));

        // Revoke application
        let mut app_revoked = ac.apps.get("app:notes").unwrap().clone();
        app_revoked.revoke_app();
        ac.register_app(app_revoked);

        assert!(matches!(
            ac.check_permission("app:notes", &Permission::ReadEntities),
            Err(SecurityError::AppRevoked(_))
        ));
    }
}
