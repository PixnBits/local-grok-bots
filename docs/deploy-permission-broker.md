# Deploy the permission broker hook

Build both binaries with `deploy/build.sh`. Paths come from `LGB_REPO` and `LGB_OUT_DIR`, or from the two arguments. The defaults are the current directory and `/var/tmp/lgb-build-placeholder`. The script does not fetch or install.

The full install steps, the parent-directory check, an empty `hook_path`, the empty `PATH` warning, and the admin re-pin are in [permission-broker.md](permission-broker.md).

Short form: install `lgb-permhook` as `root:root` mode `0755` at `/usr/local/bin/lgb-permhook`. The directory and every parent up to `/` must not be group or world writable. A mode `0775` directory fails that check even when the file itself is `0755` and owned by root. Set `[cli.permission] hook_path` to that absolute path, or leave it empty to use `lgb-permhook` beside the daemon binary. After replacing the hook, an admin calls `POST /api/permbroker/hook/repin`.
