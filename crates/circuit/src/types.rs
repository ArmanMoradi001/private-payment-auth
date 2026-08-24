//! Core circuit identifiers.

use core::fmt;

use crypto_core::Digest;

/// Identifies a node within a single [`crate::Circuit`].
///
/// Node ids are assigned deterministically in construction order
/// (`0, 1, 2, ...`), so they double as positional indices into the
/// circuit's node vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(u32);

impl NodeId {
    /// Wraps a raw index as a node id.
    pub fn new(index: u32) -> Self {
        Self(index)
    }

    /// Returns the underlying index.
    pub fn get(self) -> u32 {
        self.0
    }

    /// Returns the underlying index as `usize`.
    pub fn as_usize(self) -> usize {
        self.0 as usize
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Semantic identity of a circuit.
///
/// Computed as a domain-separated SHA-256 hash of the canonical
/// encoding; see [`crate::identity`]. Any change to constants,
/// operations, or node ordering changes the id.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CircuitId(Digest);

impl CircuitId {
    /// Wraps a digest as a circuit id.
    pub fn from_digest(digest: Digest) -> Self {
        Self(digest)
    }

    /// Borrows the underlying digest.
    pub fn as_digest(&self) -> &Digest {
        &self.0
    }
}

impl fmt::Debug for CircuitId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CircuitId({})", self.0)
    }
}

impl fmt::Display for CircuitId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_ids_wrap_raw_indices() {
        let id = NodeId::new(7);
        assert_eq!(id.get(), 7);
        assert_eq!(id.as_usize(), 7);
        assert_eq!(id.to_string(), "7");
        assert!(NodeId::new(1) < NodeId::new(2));
    }

    #[test]
    fn circuit_ids_display_hex() {
        let digest = Digest::new([0xab; 32]);
        let id = CircuitId::from_digest(digest);
        assert_eq!(format!("{id:?}").len(), "CircuitId(0x".len() + 64 + 1);
        assert_eq!(format!("{id}"), format!("{digest}"));
    }
}
