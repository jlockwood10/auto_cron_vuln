# auto_cron_vuln

`cron_enum.sh` — a read-only scheduled-job enumerator and automatic
local-privilege-escalation finder for Linux. It dumps every cron source on a
box, works out what the current user can write to, and cross-references the two
to auto-flag any scheduled job that's abusable for privesc.

> **Authorised testing only.** Intended for lab / OSCP-style use on instances
> you own or are explicitly permitted to assess. The script is **read-only** —
> it makes no changes and runs fine as an unprivileged user.

## What it does

1. **Enumerates every cron source** — system crontab, `/etc/cron.*`, per-user
   crontabs, and systemd timers.
2. **Maps what you can write** — directories and files writable by the current
   user.
3. **Auto-flags abusable jobs** by cross-referencing the two:
   - **writable script** referenced by a job → overwrite it (`CRIT`)
   - **writable directory** holding that script → delete + replace (`HIGH`)
   - **relative command + writable `PATH` dir** → `PATH` hijack
   - **wildcard (`*`)** in the command → argument / wildcard injection

   It also **reads inside each referenced script** and follows what it calls or
   sources, up to 3 levels deep — so a root-owned job that pulls in a writable
   helper or config further down the chain is still caught.
4. **Shows the next fire time** for every job (e.g. `next: in 3m`) so you know
   which to target first.

## Usage

```bash
bash cron_enum.sh            # full run
bash cron_enum.sh --no-find  # skip the slow `find /` writable sweep
```

## Requirements

- `bash` (plus standard coreutils / `grep` / `awk`).
- `python3` or `python` is **optional** — used only for exact next-run times.
  Without it, the tool falls back to a plain-text schedule description.

## Output

Findings are grouped by severity (`CRIT` / `HIGH`) with the location and the
specific abuse path. No exploitation is performed — the tool points at the
weakness; acting on it is up to you, on systems you're authorised to test.
