// Copyright 2015 The Kubernetes Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Package alwayspullimages contains an admission controller that modifies every new Pod to force
//! the image pull policy to Always. This is useful in a multitenant cluster so that users can be
//! assured that their private images can only be used by those who have the credentials to pull
//! them. Without this admission controller, once an image has been pulled to a node, any pod from
//! any user can use it simply by knowing the image's name (assuming the Pod is scheduled onto the
//! right node), without any authorization check against the image. With this admission controller
//! enabled, images are always pulled prior to starting containers, which means valid credentials are
//! required.

use std::collections::HashSet;
use std::io::Read;

// 假设的 Kubernetes API 类型和 trait
// 实际使用时需要引入 k8s-openapi 或类似的 crate

/// Plugin name constant
pub const PLUGIN_NAME: &str = "AlwaysPullImages";

/// Admission operation types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Create,
    Update,
    Delete,
    Connect,
}

/// Image pull policy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PullPolicy {
    Always,
    IfNotPresent,
    Never,
}

impl std::fmt::Display for PullPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PullPolicy::Always => write!(f, "Always"),
            PullPolicy::IfNotPresent => write!(f, "IfNotPresent"),
            PullPolicy::Never => write!(f, "Never"),
        }
    }
}

/// Container specification
#[derive(Debug, Clone)]
pub struct Container {
    pub name: String,
    pub image: String,
    pub image_pull_policy: PullPolicy,
}

/// Image volume source
#[derive(Debug, Clone)]
pub struct ImageVolumeSource {
    pub pull_policy: PullPolicy,
}

/// Volume specification
#[derive(Debug, Clone)]
pub struct Volume {
    pub name: String,
    pub image: Option<ImageVolumeSource>,
}

/// Pod specification
#[derive(Debug, Clone)]
pub struct PodSpec {
    pub containers: Vec<Container>,
    pub init_containers: Vec<Container>,
    pub ephemeral_containers: Vec<Container>,
    pub volumes: Vec<Volume>,
}

/// Pod resource
#[derive(Debug, Clone)]
pub struct Pod {
    pub spec: PodSpec,
}

/// Field path for error reporting
#[derive(Debug, Clone)]
pub struct FieldPath {
    segments: Vec<String>,
}

impl FieldPath {
    pub fn new(root: &str) -> Self {
        Self {
            segments: vec![root.to_string()],
        }
    }

    pub fn child(&self, name: &str) -> Self {
        let mut segments = self.segments.clone();
        segments.push(name.to_string());
        Self { segments }
    }

    pub fn index(&self, i: usize) -> Self {
        let mut segments = self.segments.clone();
        segments.push(format!("[{}]", i));
        Self { segments }
    }

    pub fn to_string(&self) -> String {
        self.segments.join(".")
    }
}

/// Admission attributes
pub trait Attributes {
    fn get_operation(&self) -> Operation;
    fn get_subresource(&self) -> &str;
    fn get_resource_group_resource(&self) -> (&str, &str);
    fn get_object(&self) -> Option<&Pod>;
    fn get_old_object(&self) -> Option<&Pod>;
    fn get_object_mut(&mut self) -> Option<&mut Pod>;
}

/// Error types
#[derive(Debug)]
pub enum AdmissionError {
    BadRequest(String),
    Forbidden(String),
    Aggregate(Vec<AdmissionError>),
}

impl std::fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdmissionError::BadRequest(msg) => write!(f, "BadRequest: {}", msg),
            AdmissionError::Forbidden(msg) => write!(f, "Forbidden: {}", msg),
            AdmissionError::Aggregate(errs) => {
                write!(f, "Multiple errors: ")?;
                for err in errs {
                    write!(f, "{}, ", err)?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for AdmissionError {}

type Result<T> = std::result::Result<T, AdmissionError>;

/// Mutation interface
pub trait MutationInterface {
    fn admit(&mut self, attributes: &mut dyn Attributes) -> Result<()>;
}

/// Validation interface
pub trait ValidationInterface {
    fn validate(&self, attributes: &dyn Attributes) -> Result<()>;
}

/// AlwaysPullImages admission controller
pub struct AlwaysPullImages {
    supported_operations: Vec<Operation>,
}

impl AlwaysPullImages {
    /// Create a new AlwaysPullImages admission controller
    pub fn new() -> Self {
        Self {
            supported_operations: vec![Operation::Create, Operation::Update],
        }
    }

    /// Visit all containers in a pod spec with a callback
    fn visit_containers_with_path<F>(spec: &PodSpec, base_path: &FieldPath, mut f: F)
    where
        F: FnMut(&Container, &FieldPath) -> bool,
    {
        // Visit init containers
        for (i, container) in spec.init_containers.iter().enumerate() {
            let path = base_path.child("initContainers").index(i);
            if !f(container, &path) {
                return;
            }
        }

        // Visit regular containers
        for (i, container) in spec.containers.iter().enumerate() {
            let path = base_path.child("containers").index(i);
            if !f(container, &path) {
                return;
            }
        }

        // Visit ephemeral containers
        for (i, container) in spec.ephemeral_containers.iter().enumerate() {
            let path = base_path.child("ephemeralContainers").index(i);
            if !f(container, &path) {
                return;
            }
        }
    }

    /// Visit all containers mutably
    fn visit_containers_with_path_mut<F>(spec: &mut PodSpec, base_path: &FieldPath, mut f: F)
    where
        F: FnMut(&mut Container, &FieldPath) -> bool,
    {
        // Visit init containers
        for (i, container) in spec.init_containers.iter_mut().enumerate() {
            let path = base_path.child("initContainers").index(i);
            if !f(container, &path) {
                return;
            }
        }

        // Visit regular containers
        for (i, container) in spec.containers.iter_mut().enumerate() {
            let path = base_path.child("containers").index(i);
            if !f(container, &path) {
                return;
            }
        }

        // Visit ephemeral containers
        for (i, container) in spec.ephemeral_containers.iter_mut().enumerate() {
            let path = base_path.child("ephemeralContainers").index(i);
            if !f(container, &path) {
                return;
            }
        }
    }

    /// Check if the attributes should be ignored
    fn should_ignore(attributes: &dyn Attributes) -> bool {
        // Ignore all calls to subresources or resources other than pods
        if !attributes.get_subresource().is_empty() {
            return true;
        }

        let (group, resource) = attributes.get_resource_group_resource();
        if group != "" || resource != "pods" {
            return true;
        }

        if Self::is_update_with_no_new_images(attributes) {
            return true;
        }

        false
    }

    /// Check if it's an update with no new images
    fn is_update_with_no_new_images(attributes: &dyn Attributes) -> bool {
        if attributes.get_operation() != Operation::Update {
            return false;
        }

        let pod = match attributes.get_object() {
            Some(p) => p,
            None => {
                log::warn!("Resource was marked with kind Pod but pod was unable to be converted.");
                return false;
            }
        };

        let old_pod = match attributes.get_old_object() {
            Some(p) => p,
            None => {
                log::warn!("Resource was marked with kind Pod but old pod was unable to be converted.");
                return false;
            }
        };

        let mut old_images = HashSet::new();
        Self::visit_containers_with_path(&old_pod.spec, &FieldPath::new("spec"), |c, _| {
            old_images.insert(c.image.clone());
            true
        });

        let mut has_new_image = false;
        Self::visit_containers_with_path(&pod.spec, &FieldPath::new("spec"), |c, _| {
            if !old_images.contains(&c.image) {
                has_new_image = true;
            }
            !has_new_image
        });

        !has_new_image
    }
}

impl Default for AlwaysPullImages {
    fn default() -> Self {
        Self::new()
    }
}

impl MutationInterface for AlwaysPullImages {
    fn admit(&mut self, attributes: &mut dyn Attributes) -> Result<()> {
        // Ignore all calls to subresources or resources other than pods
        if Self::should_ignore(attributes) {
            return Ok(());
        }

        let pod = attributes.get_object_mut().ok_or_else(|| {
            AdmissionError::BadRequest(
                "Resource was marked with kind Pod but was unable to be converted".to_string(),
            )
        })?;

        Self::visit_containers_with_path_mut(&mut pod.spec, &FieldPath::new("spec"), |c, _| {
            c.image_pull_policy = PullPolicy::Always;
            true
        });

        // See: https://kep.k8s.io/4639
        for volume in &mut pod.spec.volumes {
            if let Some(ref mut image) = volume.image {
                image.pull_policy = PullPolicy::Always;
            }
        }

        Ok(())
    }
}

impl ValidationInterface for AlwaysPullImages {
    fn validate(&self, attributes: &dyn Attributes) -> Result<()> {
        if Self::should_ignore(attributes) {
            return Ok(());
        }

        let pod = attributes.get_object().ok_or_else(|| {
            AdmissionError::BadRequest(
                "Resource was marked with kind Pod but was unable to be converted".to_string(),
            )
        })?;

        let mut all_errs = Vec::new();

        Self::visit_containers_with_path(&pod.spec, &FieldPath::new("spec"), |c, p| {
            if c.image_pull_policy != PullPolicy::Always {
                all_errs.push(AdmissionError::Forbidden(format!(
                    "Unsupported value: {:?}: supported values: \"Always\" at {}",
                    c.image_pull_policy,
                    p.child("imagePullPolicy").to_string()
                )));
            }
            true
        });

        // See: https://kep.k8s.io/4639
        for (i, volume) in pod.spec.volumes.iter().enumerate() {
            if let Some(ref image) = volume.image {
                if image.pull_policy != PullPolicy::Always {
                    all_errs.push(AdmissionError::Forbidden(format!(
                        "Unsupported value: {:?}: supported values: \"Always\" at {}",
                        image.pull_policy,
                        FieldPath::new("spec")
                            .child("volumes")
                            .index(i)
                            .child("image")
                            .child("pullPolicy")
                            .to_string()
                    )));
                }
            }
        }

        if !all_errs.is_empty() {
            return Err(AdmissionError::Aggregate(all_errs));
        }

        Ok(())
    }
}

/// Register the plugin
pub fn register<R: Read>(
    _config: R,
) -> Result<Box<dyn MutationInterface + ValidationInterface>> {
    Ok(Box::new(AlwaysPullImages::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_always_pull_images_creation() {
        let plugin = AlwaysPullImages::new();
        assert_eq!(plugin.supported_operations.len(), 2);
    }
}
