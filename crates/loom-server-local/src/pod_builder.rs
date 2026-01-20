// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

use crate::weaver::{LocalWeaver, WeaverStatus};
use k8s_openapi::api::core::v1::{Container, ContainerStatus, Pod, PodSpec, PodStatus};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use std::collections::BTreeMap;

pub fn local_weaver_to_pod(weaver: &LocalWeaver) -> Pod {
	let mut labels = weaver.metadata.labels.clone();
	labels.insert("loom.dev/managed".to_string(), "true".to_string());
	labels.insert(
		"loom.dev/weaver-id".to_string(),
		weaver.metadata.id.clone(),
	);

	// Add owner-user-id label (spec §5 - optional, defaults "")
	let owner = weaver
		.metadata
		.labels
		.get("loom.dev/owner-user-id")
		.cloned()
		.unwrap_or_default();
	labels.insert("loom.dev/owner-user-id".to_string(), owner);

	// Build annotations per spec §5
	let mut annotations = BTreeMap::new();
	annotations.insert("loom.dev/tags".to_string(), "{}".to_string());
	annotations.insert(
		"loom.dev/lifetime-hours".to_string(),
		weaver
			.metadata
			.ttl_hours
			.map(|h| h.to_string())
			.unwrap_or_else(|| "4".to_string()),
	);
	if !weaver.metadata.working_dir.as_os_str().is_empty() {
		annotations.insert(
			"loom.dev/working-dir".to_string(),
			weaver.metadata.working_dir.display().to_string(),
		);
	}

	let container = Container {
		name: "loom".to_string(),
		image: Some(weaver.metadata.image.clone()),
		..Default::default()
	};

	let container_status = ContainerStatus {
		name: "loom".to_string(),
		ready: weaver.status == WeaverStatus::Running,
		started: Some(weaver.status == WeaverStatus::Running),
		..Default::default()
	};

	Pod {
		metadata: ObjectMeta {
			name: Some(weaver.metadata.name.clone()),
			namespace: Some("local".to_string()),
			labels: Some(labels),
			annotations: Some(annotations),
			creation_timestamp: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
				weaver.metadata.created_at,
			)),
			..Default::default()
		},
		spec: Some(PodSpec {
			containers: vec![container],
			..Default::default()
		}),
		status: Some(PodStatus {
			phase: Some(weaver.status.to_phase().to_string()),
			container_statuses: Some(vec![container_status]),
			..Default::default()
		}),
	}
}

pub fn parse_weaver_id(pod_name: &str) -> Option<String> {
	pod_name.strip_prefix("weaver-").map(|s| s.to_string())
}

pub fn matches_selector(labels: &BTreeMap<String, String>, selector: &str) -> bool {
	if selector.is_empty() {
		return true;
	}

	for part in selector.split(',') {
		let part = part.trim();
		if part.is_empty() {
			continue;
		}

		if let Some((key, value)) = part.split_once('=') {
			let key = key.trim();
			let value = value.trim();

			match labels.get(key) {
				Some(label_value) if label_value == value => continue,
				_ => return false,
			}
		} else if !labels.contains_key(part) {
			return false;
		}
	}

	true
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_parse_weaver_id() {
		assert_eq!(
			parse_weaver_id("weaver-abc123"),
			Some("abc123".to_string())
		);
		assert_eq!(parse_weaver_id("not-a-weaver"), None);
		assert_eq!(parse_weaver_id("weaver-"), Some("".to_string()));
	}

	#[test]
	fn test_matches_selector_empty() {
		let labels = BTreeMap::new();
		assert!(matches_selector(&labels, ""));
	}

	#[test]
	fn test_matches_selector_single() {
		let mut labels = BTreeMap::new();
		labels.insert("app".to_string(), "loom".to_string());

		assert!(matches_selector(&labels, "app=loom"));
		assert!(!matches_selector(&labels, "app=other"));
		assert!(!matches_selector(&labels, "missing=value"));
	}

	#[test]
	fn test_matches_selector_multiple() {
		let mut labels = BTreeMap::new();
		labels.insert("app".to_string(), "loom".to_string());
		labels.insert("env".to_string(), "dev".to_string());

		assert!(matches_selector(&labels, "app=loom,env=dev"));
		assert!(!matches_selector(&labels, "app=loom,env=prod"));
	}
}
