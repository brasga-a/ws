# Single-mount userspace VFS daemon

All `Views` are exposed as subdirectories under a single userspace virtual filesystem mount (`<mount>/<view-id>/`) served by a background daemon rather than through per-`View` mounts or host filesystem reflinks/hardlinks. Per-`View` mounts hit OS mount-table overhead at thousands of concurrent `Views`, while reflinks and hardlinks fail on filesystems such as `ext4` and still multiply directory entries and inodes linearly per `View`.
