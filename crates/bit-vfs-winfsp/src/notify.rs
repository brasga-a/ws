//! Directory change notification hook (`DirectoryChangeNotifier`) backing Windows
//! `ReadDirectoryChangesW` and WinFsp `FspFileSystemNotify` callbacks.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::ops::{BitAnd, BitOr, BitOrAssign};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use bit_core::vfs::MountPath;

use crate::status::{NtStatus, STATUS_INVALID_HANDLE};

/// Win32 `FILE_ACTION_*` event kind delivered to `ReadDirectoryChangesW` watchers.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DirectoryChangeAction {
    /// `FILE_ACTION_ADDED` (`0x0000_0001`).
    Added = 1,
    /// `FILE_ACTION_REMOVED` (`0x0000_0002`).
    Removed = 2,
    /// `FILE_ACTION_MODIFIED` (`0x0000_0003`).
    Modified = 3,
    /// `FILE_ACTION_RENAMED_OLD_NAME` (`0x0000_0004`).
    RenamedOldName = 4,
    /// `FILE_ACTION_RENAMED_NEW_NAME` (`0x0000_0005`).
    RenamedNewName = 5,
}

impl DirectoryChangeAction {
    /// Returns the raw Win32 `FILE_ACTION_*` numeric code.
    pub const fn code(self) -> u32 {
        self as u32
    }
}

/// Win32 `FILE_NOTIFY_CHANGE_*` filter mask used by `ReadDirectoryChangesW`.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct NotifyFilter(pub u32);

impl NotifyFilter {
    /// `FILE_NOTIFY_CHANGE_FILE_NAME` (`0x0000_0001`).
    pub const FILE_NAME: Self = Self(0x0000_0001);
    /// `FILE_NOTIFY_CHANGE_DIR_NAME` (`0x0000_0002`).
    pub const DIR_NAME: Self = Self(0x0000_0002);
    /// `FILE_NOTIFY_CHANGE_ATTRIBUTES` (`0x0000_0004`).
    pub const ATTRIBUTES: Self = Self(0x0000_0004);
    /// `FILE_NOTIFY_CHANGE_SIZE` (`0x0000_0008`).
    pub const SIZE: Self = Self(0x0000_0008);
    /// `FILE_NOTIFY_CHANGE_LAST_WRITE` (`0x0000_0010`).
    pub const LAST_WRITE: Self = Self(0x0000_0010);
    /// `FILE_NOTIFY_CHANGE_CREATION` (`0x0000_0040`).
    pub const CREATION: Self = Self(0x0000_0040);
    /// `FILE_NOTIFY_CHANGE_SECURITY` (`0x0000_0100`).
    pub const SECURITY: Self = Self(0x0000_0100);
    /// Combined mask matching all standard file and directory change classes.
    pub const ALL: Self = Self(
        Self::FILE_NAME.0
            | Self::DIR_NAME.0
            | Self::ATTRIBUTES.0
            | Self::SIZE.0
            | Self::LAST_WRITE.0
            | Self::CREATION.0
            | Self::SECURITY.0,
    );

    /// Returns the raw Win32 bitmask.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Returns `true` when `self` and `other` share at least one bit.
    pub const fn intersects(self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }
}

impl BitOr for NotifyFilter {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for NotifyFilter {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl BitAnd for NotifyFilter {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

/// Opaque subscription identifier returned by [`DirectoryChangeNotifier::subscribe`].
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WatchId(pub u64);

/// Single directory change record emitted by [`WinFspFileSystem`](crate::WinFspFileSystem).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DirectoryChangeEvent {
    /// Full mount-relative Windows path using `\` separators (e.g. `\view-1\src\lib.rs`).
    pub mount_win_path: String,
    /// Path relative to the watched directory using `\` separators (e.g. `src\lib.rs`).
    pub relative_win_path: String,
    /// `FILE_ACTION_*` event kind.
    pub action: DirectoryChangeAction,
    /// `FILE_NOTIFY_CHANGE_*` bits triggered by this mutation.
    pub filter: NotifyFilter,
    /// Whether the mutated entry is a directory.
    pub is_directory: bool,
}

/// Listener hook signature invoked immediately for WinFsp `FspFileSystemNotify` forwarding.
pub type DirectoryChangeListener = Arc<dyn Fn(&DirectoryChangeEvent) + Send + Sync>;

struct WatchSubscription {
    watch_mount_path: String,
    watch_tree: bool,
    filter: NotifyFilter,
    queue: VecDeque<DirectoryChangeEvent>,
}

struct NotifierInner {
    next_id: u64,
    watches: BTreeMap<WatchId, WatchSubscription>,
    listeners: Vec<DirectoryChangeListener>,
}

/// Thread-safe directory change notification hub backing `ReadDirectoryChangesW` watches and
/// WinFsp `FspFileSystemNotify` host hooks.
pub struct DirectoryChangeNotifier {
    inner: Mutex<NotifierInner>,
    cvar: Condvar,
}

impl fmt::Debug for DirectoryChangeNotifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        f.debug_struct("DirectoryChangeNotifier")
            .field("watch_count", &guard.watches.len())
            .field("listener_count", &guard.listeners.len())
            .finish()
    }
}

impl Default for DirectoryChangeNotifier {
    fn default() -> Self {
        Self::new()
    }
}

impl DirectoryChangeNotifier {
    /// Creates an empty [`DirectoryChangeNotifier`].
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(NotifierInner {
                next_id: 1,
                watches: BTreeMap::new(),
                listeners: Vec::new(),
            }),
            cvar: Condvar::new(),
        }
    }

    /// Registers a push listener invoked for every emitted [`DirectoryChangeEvent`].
    pub fn add_listener(&self, listener: DirectoryChangeListener) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.listeners.push(listener);
    }

    /// Registers a `ReadDirectoryChangesW` watch on `raw_watch_path` (`\` or `\view-id\...`).
    pub fn subscribe(
        &self,
        raw_watch_path: &str,
        watch_tree: bool,
        filter: NotifyFilter,
    ) -> Result<WatchId, NtStatus> {
        let parsed = MountPath::parse_winfsp(raw_watch_path)?;
        Ok(self.subscribe_canonical(&parsed.to_mount_string(), watch_tree, filter))
    }

    /// Registers a watch directly on a canonical `'/'`-separated mount-relative directory path.
    pub(crate) fn subscribe_canonical(
        &self,
        canonical_mount_dir: &str,
        watch_tree: bool,
        filter: NotifyFilter,
    ) -> WatchId {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let id = WatchId(guard.next_id);
        guard.next_id += 1;
        guard.watches.insert(
            id,
            WatchSubscription {
                watch_mount_path: canonical_mount_dir.to_owned(),
                watch_tree,
                filter,
                queue: VecDeque::new(),
            },
        );
        id
    }

    /// Cancels an active watch subscription, returning `true` if it existed.
    pub fn unsubscribe(&self, watch_id: WatchId) -> bool {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let removed = guard.watches.remove(&watch_id).is_some();
        if removed {
            self.cvar.notify_all();
        }
        removed
    }

    /// Drains all queued events for `watch_id` without blocking.
    pub fn poll_events(&self, watch_id: WatchId) -> Result<Vec<DirectoryChangeEvent>, NtStatus> {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let sub = guard
            .watches
            .get_mut(&watch_id)
            .ok_or(STATUS_INVALID_HANDLE)?;
        Ok(sub.queue.drain(..).collect())
    }

    /// Blocks up to `timeout` until at least one event arrives for `watch_id` (returning an empty
    /// `Vec` on timeout, or [`STATUS_INVALID_HANDLE`] if `watch_id` is unsubscribed).
    pub fn wait_for_events(
        &self,
        watch_id: WatchId,
        timeout: Duration,
    ) -> Result<Vec<DirectoryChangeEvent>, NtStatus> {
        let deadline = Instant::now() + timeout;
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            let Some(sub) = guard.watches.get_mut(&watch_id) else {
                return Err(STATUS_INVALID_HANDLE);
            };
            if !sub.queue.is_empty() {
                return Ok(sub.queue.drain(..).collect());
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(Vec::new());
            }
            let remaining = deadline.duration_since(now);
            let (next_guard, wait_res) = self
                .cvar
                .wait_timeout(guard, remaining)
                .unwrap_or_else(|e| e.into_inner());
            guard = next_guard;
            if wait_res.timed_out() {
                let sub = guard
                    .watches
                    .get_mut(&watch_id)
                    .ok_or(STATUS_INVALID_HANDLE)?;
                return Ok(sub.queue.drain(..).collect());
            }
        }
    }

    /// Emits a filesystem mutation event on canonical mount-relative `mount_path` (`"view/a/b"`).
    pub fn emit(
        &self,
        mount_path: &str,
        action: DirectoryChangeAction,
        filter: NotifyFilter,
        is_directory: bool,
    ) {
        if mount_path.is_empty() {
            return;
        }
        let mount_win_path = format!(r"\{}", mount_path.replace('/', r"\"));

        let listeners: Vec<DirectoryChangeListener> = {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let mut matched_any = false;

            for sub in guard.watches.values_mut() {
                if !sub.filter.intersects(filter) {
                    continue;
                }
                let Some(rel_posix) =
                    relative_if_within(&sub.watch_mount_path, mount_path, sub.watch_tree)
                else {
                    continue;
                };
                let relative_win_path = rel_posix.replace('/', r"\");
                sub.queue.push_back(DirectoryChangeEvent {
                    mount_win_path: mount_win_path.clone(),
                    relative_win_path,
                    action,
                    filter,
                    is_directory,
                });
                matched_any = true;
            }

            if matched_any {
                self.cvar.notify_all();
            }

            guard.listeners.clone()
        };

        if !listeners.is_empty() {
            let root_event = DirectoryChangeEvent {
                mount_win_path,
                relative_win_path: mount_path.replace('/', r"\"),
                action,
                filter,
                is_directory,
            };
            for listener in listeners {
                listener(&root_event);
            }
        }
    }
}

fn relative_if_within<'a>(
    watch_dir: &str,
    target_path: &'a str,
    watch_tree: bool,
) -> Option<&'a str> {
    let rel = if watch_dir.is_empty() {
        target_path
    } else {
        let rest = target_path.strip_prefix(watch_dir)?;
        rest.strip_prefix('/')?
    };

    if rel.is_empty() {
        return None;
    }
    if !watch_tree && rel.contains('/') {
        return None;
    }
    Some(rel)
}
