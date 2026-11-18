# Strictly Git-agnostic scope

Although motivated by replacing `git worktree`, the entire project treats `.git/` as an ordinary directory and contains no Git-specific logic in either the core or the CLI. Keeping the tool purely at the directory-tree level preserves UNIX generality across any toolchain or VCS, while standard Git commands (such as `git fetch <view-path>`) and external scripts remain sufficient to exchange commits or tune Git behavior.
