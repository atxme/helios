//! The ceremonies, as things a caller drives rather than as commands.
//!
//! Each one splits at the same seam: a verification that produces the typed
//! manifest §12.2 requires, and an approval that runs the gesture. Nothing
//! here prints, prompts, or reads a path from an argument — those belong to
//! whatever drives it, and the point of the split is that a terminal and a
//! window can both do so without either shape leaking into the other.

pub mod recovery;
