# Flat Base and Overlay composition

Every `View` is composed of exactly one immutable `Base` and one private `Overlay`; `Overlays` never stack directly on top of one another. Branching from a `View` requires a `Freeze` into a new `Base`, keeping path resolution `O(1)` regardless of branching history and preventing lifecycle coupling where mutating or deleting one `View` could affect another.
