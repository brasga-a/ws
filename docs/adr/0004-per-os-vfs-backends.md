# Per-OS VFS backends: FUSE, loopback NFSv3, and WinFsp

Each target operating system uses a thin protocol adapter over the OS-agnostic core that preserves true read-path virtualization without kernel extensions on Apple Silicon or physical read hydration on Windows:
- **Linux**: FUSE (`/dev/fuse` via unprivileged `fusermount3`).
- **macOS**: A userspace loopback NFSv3 server bound to `127.0.0.1` (`locallocks`, owner `uid` check), rejecting `macFUSE` because third-party kernel extensions require booting Apple Silicon Macs into Recovery Mode with Reduced Security. We accept the macOS trade-off that `FSEvents` does not emit push events on NFS mounts (relying on `kqueue`, polling, or Watchman until a future `FSKit` backend).
- **Windows**: `WinFsp`, rejecting `ProjFS` because `ProjFS` physically hydrates every read file onto NTFS, which would duplicate files across hundreds of `Views` during builds.
