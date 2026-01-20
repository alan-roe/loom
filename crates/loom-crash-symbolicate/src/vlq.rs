// Copyright (c) 2025 Geoffrey Huntley <ghuntley@ghuntley.com>. All rights reserved.
// SPDX-License-Identifier: Proprietary

//! VLQ (Variable-Length Quantity) decoder for source map mappings.
//!
//! Source maps use Base64 VLQ encoding for compact storage of line/column mappings.
//! This module provides decoding functionality following the source map v3 spec.

use crate::error::{Result, SymbolicateError};

/// Base64 character set used in VLQ encoding.
const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Decode a Base64 character to its 6-bit value.
fn decode_char(ch: u8) -> Result<i32> {
	BASE64_CHARS
		.iter()
		.position(|&c| c == ch)
		.map(|pos| pos as i32)
		.ok_or_else(|| SymbolicateError::InvalidVlqChar(ch as char))
}

/// Decode a VLQ-encoded segment into a vector of signed integers.
///
/// Each segment represents one or more values:
/// - Minimum 1 value: generated column offset
/// - Optional 4 more values: source index, original line, original column, name index
pub fn decode_vlq_segment(segment: &str) -> Result<Vec<i32>> {
	let mut values = Vec::new();
	let mut value = 0i32;
	let mut shift = 0;

	for ch in segment.bytes() {
		let digit = decode_char(ch)?;

		// Continuation bit is the 6th bit (0b100000 = 32)
		let continuation = digit & 0b100000 != 0;
		let digit_value = digit & 0b011111;

		value += digit_value << shift;
		shift += 5;

		if !continuation {
			// Convert from sign-magnitude to two's complement
			// The lowest bit indicates the sign: 1 = negative, 0 = positive
			let negated = value & 1 != 0;
			value >>= 1;
			if negated {
				value = -value;
			}
			values.push(value);
			value = 0;
			shift = 0;
		}
	}

	Ok(values)
}

/// A single mapping entry in the decoded source map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapping {
	/// Line in the generated file (0-indexed).
	pub generated_line: u32,
	/// Column in the generated file (0-indexed).
	pub generated_column: u32,
	/// Index into the sources array.
	pub source_index: u32,
	/// Line in the original file (0-indexed).
	pub original_line: u32,
	/// Column in the original file (0-indexed).
	pub original_column: u32,
	/// Optional index into the names array.
	pub name_index: Option<u32>,
}

/// Container for decoded mappings with efficient lookup.
#[derive(Debug, Clone, Default)]
pub struct DecodedMappings {
	/// Mappings sorted by generated line, then generated column.
	mappings: Vec<Mapping>,
}

impl DecodedMappings {
	pub fn new() -> Self {
		Self {
			mappings: Vec::new(),
		}
	}

	pub fn add(&mut self, mapping: Mapping) {
		self.mappings.push(mapping);
	}

	/// Find the mapping for a given generated line and column.
	/// Uses binary search to find the closest mapping at or before the given position.
	pub fn find(&self, line: u32, column: u32) -> Option<&Mapping> {
		// First, find all mappings on this line
		let line_start = self
			.mappings
			.partition_point(|m| m.generated_line < line);
		let line_end = self
			.mappings
			.partition_point(|m| m.generated_line <= line);

		if line_start >= line_end {
			return None;
		}

		let line_mappings = &self.mappings[line_start..line_end];

		// Find the closest mapping at or before the given column
		let idx = line_mappings.partition_point(|m| m.generated_column <= column);

		if idx == 0 {
			// Column is before all mappings on this line
			None
		} else {
			Some(&line_mappings[idx - 1])
		}
	}

	pub fn len(&self) -> usize {
		self.mappings.len()
	}

	pub fn is_empty(&self) -> bool {
		self.mappings.is_empty()
	}
}

/// Decode VLQ-encoded source map mappings string into structured form.
///
/// The mappings string format:
/// - Lines are separated by semicolons (;)
/// - Segments within a line are separated by commas (,)
/// - Each segment contains 1, 4, or 5 VLQ-encoded values
pub fn decode_vlq_mappings(mappings: &str) -> Result<DecodedMappings> {
	let mut result = DecodedMappings::new();
	let mut generated_line = 0u32;

	// State for relative decoding (values are delta-encoded)
	let mut prev_source = 0i32;
	let mut prev_original_line = 0i32;
	let mut prev_original_column = 0i32;
	let mut prev_name = 0i32;

	for line in mappings.split(';') {
		let mut generated_column = 0i32;

		for segment in line.split(',') {
			if segment.is_empty() {
				continue;
			}

			let values = decode_vlq_segment(segment)?;

			if values.is_empty() {
				continue;
			}

			// First value is always the generated column (relative)
			generated_column += values[0];

			// If we have 4+ values, we have source information
			if values.len() >= 4 {
				prev_source += values[1];
				prev_original_line += values[2];
				prev_original_column += values[3];

				let name_index = if values.len() >= 5 {
					prev_name += values[4];
					Some(prev_name as u32)
				} else {
					None
				};

				result.add(Mapping {
					generated_line,
					generated_column: generated_column as u32,
					source_index: prev_source as u32,
					original_line: prev_original_line as u32,
					original_column: prev_original_column as u32,
					name_index,
				});
			}
		}

		generated_line += 1;
	}

	Ok(result)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_decode_vlq_segment_simple() {
		// 'A' = 0
		let values = decode_vlq_segment("A").unwrap();
		assert_eq!(values, vec![0]);

		// 'C' = 1
		let values = decode_vlq_segment("C").unwrap();
		assert_eq!(values, vec![1]);

		// 'D' = -1
		let values = decode_vlq_segment("D").unwrap();
		assert_eq!(values, vec![-1]);
	}

	#[test]
	fn test_decode_vlq_segment_multi_value() {
		// AAAA = 0, 0, 0, 0
		let values = decode_vlq_segment("AAAA").unwrap();
		assert_eq!(values, vec![0, 0, 0, 0]);

		// AACA = 0, 0, 1, 0
		let values = decode_vlq_segment("AACA").unwrap();
		assert_eq!(values, vec![0, 0, 1, 0]);
	}

	#[test]
	fn test_decode_vlq_segment_continuation() {
		// Large positive number: 'gB' = 16
		let values = decode_vlq_segment("gB").unwrap();
		assert_eq!(values, vec![16]);
	}

	#[test]
	fn test_decode_vlq_mappings_simple() {
		// Single mapping: generated col 0, source 0, original line 0, original col 0
		let result = decode_vlq_mappings("AAAA").unwrap();
		assert_eq!(result.len(), 1);

		let mapping = result.find(0, 0).unwrap();
		assert_eq!(mapping.generated_line, 0);
		assert_eq!(mapping.generated_column, 0);
		assert_eq!(mapping.source_index, 0);
		assert_eq!(mapping.original_line, 0);
		assert_eq!(mapping.original_column, 0);
	}

	#[test]
	fn test_decode_vlq_mappings_multi_line() {
		// Two lines with one mapping each
		let result = decode_vlq_mappings("AAAA;AACA").unwrap();
		assert_eq!(result.len(), 2);

		let first = result.find(0, 0).unwrap();
		assert_eq!(first.generated_line, 0);
		assert_eq!(first.original_line, 0);

		let second = result.find(1, 0).unwrap();
		assert_eq!(second.generated_line, 1);
		// Original line is relative, so 0 + 1 = 1
		assert_eq!(second.original_line, 1);
	}

	#[test]
	fn test_mapping_find_closest() {
		let mut mappings = DecodedMappings::new();

		// Add mappings at columns 0, 10, 20 on line 0
		mappings.add(Mapping {
			generated_line: 0,
			generated_column: 0,
			source_index: 0,
			original_line: 0,
			original_column: 0,
			name_index: None,
		});
		mappings.add(Mapping {
			generated_line: 0,
			generated_column: 10,
			source_index: 0,
			original_line: 1,
			original_column: 5,
			name_index: None,
		});
		mappings.add(Mapping {
			generated_line: 0,
			generated_column: 20,
			source_index: 0,
			original_line: 2,
			original_column: 10,
			name_index: None,
		});

		// Column 5 should map to the first mapping (closest at or before)
		let found = mappings.find(0, 5).unwrap();
		assert_eq!(found.generated_column, 0);
		assert_eq!(found.original_line, 0);

		// Column 15 should map to the second mapping
		let found = mappings.find(0, 15).unwrap();
		assert_eq!(found.generated_column, 10);
		assert_eq!(found.original_line, 1);

		// Column 25 should map to the third mapping
		let found = mappings.find(0, 25).unwrap();
		assert_eq!(found.generated_column, 20);
		assert_eq!(found.original_line, 2);
	}

	#[test]
	fn test_invalid_vlq_char() {
		let result = decode_vlq_segment("!");
		assert!(result.is_err());
	}
}
