# Bit

Isolated, writable directory trees backed by shared immutable bases, enabling thousands of concurrent views without duplicating unchanged files.

## Language

**Base**:
A sealed, immutable directory tree owned by the system and decoupled from whatever external directory originated it.
_Avoid_: Origin, source, snapshot

**Tag**:
A mutable, human-readable name pointing to a `Base`.
_Avoid_: Alias, branch, ref

**View**:
An isolated, writable directory tree composed of exactly one `Base` and one private `Overlay`.
_Avoid_: Environment, worktree, workspace

**Overlay**:
The private set of file and directory additions, modifications, and deletions belonging to a single `View`.
_Avoid_: Layer, delta, patch

**Freeze**:
The capture of a `View`'s current state as a new immutable `Base`.
_Avoid_: Commit, snapshot, promote

**Apply**:
The all-or-nothing projection of a `View`'s `Overlay` onto an external directory, leaving the `View` unchanged and guarded against changes made to that directory since the `View`'s `Base` was created.
_Avoid_: Merge, sync, export
