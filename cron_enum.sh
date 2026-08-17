#!/usr/bin/env bash
#
# cron-enum.sh  -  Scheduled-job enumeration + auto vuln finder
# -----------------------------------------------------------------------------
# Authorized lab / OSCP use on your own provisioned instances only. Read-only:
# makes no changes, runs fine as an unprivileged user.
#
# It does four things:
#   1. Dumps every cron source on the box (system, per-user, systemd timers).
#   2. Lists directories/files the current user can write to.
#   3. Cross-references the two and AUTO-FLAGS any scheduled job that is
#      abusable for local privilege escalation:
#        - writable script referenced by a job   (overwrite it)
#        - writable directory holding that script (delete + replace)
#        - relative command + writable PATH dir   (PATH hijack)
#        - wildcard (*) in the command            (argument/wildcard injection)
#      It also READS INSIDE each referenced script and follows the files it
#      calls or sources (up to 3 levels), so a root-owned job that pulls in a
#      writable helper/config down the chain still gets flagged.
#   4. Shows the NEXT FIRE TIME for every job (e.g. "next: in 3m") so you know
#      which one to target first. Exact time needs python3/python on the box;
#      without it, falls back to a plain-text schedule description.
#
# Usage:  bash cron-enum.sh            # full run
#         bash cron-enum.sh --no-find  # skip the slow  find /  writable sweep
# -----------------------------------------------------------------------------

# --- setup ------------------------------------------------------------------
DO_FIND=1
[ "${1:-}" = "--no-find" ] && DO_FIND=0

if [ -t 1 ]; then
  RED=$'\e[1;31m'; YEL=$'\e[1;33m'; GRN=$'\e[1;32m'; CYN=$'\e[1;36m'; DIM=$'\e[2m'; BLD=$'\e[1m'; RST=$'\e[0m'
else
  RED=; YEL=; GRN=; CYN=; DIM=; BLD=; RST=
fi

ME=$(id -un 2>/dev/null || whoami 2>/dev/null || echo "?")
MYID=$(id 2>/dev/null)

# cron PATH used for relative-command / PATH-hijack checks
CRON_PATH=$(grep -E '^\s*PATH=' /etc/crontab 2>/dev/null | tail -n1 | cut -d= -f2- | tr -d '"')
[ -z "$CRON_PATH" ] && CRON_PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# interpreter for exact next-run calculation (falls back to a text description)
have_py=""
command -v python3 >/dev/null 2>&1 && have_py=python3
[ -z "$have_py" ] && command -v python >/dev/null 2>&1 && have_py=python

PYNEXT=$(cat <<'PYEOF'
import sys,datetime
mn,hr,dom,mon,dow=sys.argv[1:6]
NM={'jan':1,'feb':2,'mar':3,'apr':4,'may':5,'jun':6,'jul':7,'aug':8,'sep':9,'oct':10,'nov':11,'dec':12}
ND={'sun':0,'mon':1,'tue':2,'wed':3,'thu':4,'fri':5,'sat':6}
def parse(f,lo,hi,names=None):
    s=set()
    if names:
        fl=f.lower()
        for k,v in names.items(): fl=fl.replace(k,str(v))
        f=fl
    for part in f.split(','):
        step=1; rng=part
        if '/' in part: rng,st=part.split('/'); step=int(st)
        if rng=='*' or rng=='': a,b=lo,hi
        elif '-' in rng: aa,bb=rng.split('-'); a=int(aa); b=int(bb)
        else: a=b=int(rng)
        x=a
        while x<=b: s.add(x); x+=step
    return s
try:
    mins=parse(mn,0,59); hrs=parse(hr,0,23); doms=parse(dom,1,31)
    mons=parse(mon,1,12,NM); dows=parse(dow,0,7,ND)
except Exception:
    print("?"); sys.exit(0)
if 7 in dows: dows.add(0)
dr=dom.strip()!='*'; wr=dow.strip()!='*'
now=datetime.datetime.now().replace(second=0,microsecond=0)
t=now+datetime.timedelta(minutes=1); limit=t+datetime.timedelta(days=366*4); hit=None
while t<=limit:
    if t.minute in mins and t.hour in hrs and t.month in mons:
        wd=(t.weekday()+1)%7; dm=t.day in doms; dw=wd in dows
        ok=(dm or dw) if (dr and wr) else (dm if dr else (dw if wr else True))
        if ok: hit=t; break
    t+=datetime.timedelta(minutes=1)
if hit is None: print("unknown"); sys.exit(0)
secs=int((hit-now).total_seconds())
d,r=divmod(secs,86400); h,r=divmod(r,3600); m,_=divmod(r,60)
short=("in %dd%dh"%(d,h)) if d else (("in %dh%dm"%(h,m)) if h else ("in %dm"%m))
print("%s\t%s"%(short,hit.strftime("%a %Y-%m-%d %H:%M")))
PYEOF
)

FINDINGS=()   # each entry: "SEV|location|note"
SEEN_SCRIPTS=" "   # visited-file guard for recursive script following

already_seen() { case "$SEEN_SCRIPTS" in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

hr()   { printf '%s\n' "${DIM}--------------------------------------------------------------------------${RST}"; }
sect() { printf '\n%s\n' "${CYN}${BLD}== $* ==${RST}"; }

add_finding() { FINDINGS+=("$1|$2|$3"); }

# --- helpers ----------------------------------------------------------------

# writability of a single path token that a job references
report_path() {
  local p="$1" ctx="$2" d
  [ -z "$p" ] && return
  # strip quotes and leading redirection/pipe glue
  p="${p%\"}"; p="${p#\"}"; p="${p%\'}"; p="${p#\'}"
  p="${p#>}"; p="${p#>}"; p="${p#<}"; p="${p#|}"
  case "$p" in */*) ;; *) return ;; esac   # only tokens that look like paths

  if [ -f "$p" ]; then
    [ -w "$p" ] && add_finding "CRIT" "$p" "writable file run by [$ctx] - overwrite with your payload"
    d=$(dirname -- "$p" 2>/dev/null)
    [ -n "$d" ] && [ -d "$d" ] && [ -w "$d" ] && \
      add_finding "HIGH" "$d/" "writable dir holds $p [$ctx] - delete + replace the file"
  elif [ -d "$p" ]; then
    [ -w "$p" ] && add_finding "HIGH" "$p/" "writable directory referenced by [$ctx] - you can drop files here"
  else
    d=$(dirname -- "$p" 2>/dev/null)
    [ -n "$d" ] && [ -d "$d" ] && [ -w "$d" ] && \
      add_finding "HIGH" "$d/" "$p (run by [$ctx]) is missing but its dir is writable - create it"
  fi
}

# Read INSIDE a referenced script/config and inspect what IT calls or sources,
# so a clean top-level script that pulls in a writable file still gets flagged.
# Recurses up to 3 levels; skips binaries and already-seen files.
follow_script() {
  local f="$1" ctx="$2" depth="${3:-0}" sl tok
  [ "$depth" -ge 3 ] && return
  already_seen "$f" && return
  SEEN_SCRIPTS="$SEEN_SCRIPTS$f "
  grep -Iq . "$f" 2>/dev/null || return          # skip binaries / empty files
  while IFS= read -r sl || [ -n "$sl" ]; do
    sl="${sl#"${sl%%[![:space:]]*}"}"            # ltrim
    case "$sl" in ""|\#*) continue ;; esac
    case "$sl" in
      .\ *|source\ *)                             # sourced config / library
        tok=$(awk '{print $2}' <<<"$sl")
        examine "$tok" "$ctx -> sourced by $f" "$((depth+1))"
        continue ;;
    esac
    set -f
    for tok in $sl; do                            # any path-looking token it calls
      case "$tok" in */*) examine "$tok" "$ctx -> called by $f" "$((depth+1))" ;; esac
    done
    set +f
  done < "$f"
}

# Check a token for writability AND, if it is a readable script/config, follow it.
examine() {
  local p="$1" ctx="$2" depth="${3:-0}" q
  report_path "$p" "$ctx"
  q="$p"; q="${q%\"}"; q="${q#\"}"; q="${q%\'}"; q="${q#\'}"
  q="${q#>}"; q="${q#>}"; q="${q#<}"; q="${q#|}"
  case "$q" in */*) ;; *) return ;; esac
  [ -f "$q" ] && [ -r "$q" ] && follow_script "$q" "$ctx" "$depth"
}

# best-effort schedule description when no interpreter is available
human_sched() {
  local m=$1 h=$2 dom=$3 mon=$4 dow=$5
  case "$m" in */*) [ "$h $dom $mon $dow" = "* * * *" ] && { echo "every ${m#*/}m"; return; } ;; esac
  if [ "$dom $mon $dow" = "* * *" ] && [ "$m" != "*" ] && [ "$h" != "*" ]; then
    printf 'daily %s:%s\n' "$h" "$m"; return
  fi
  echo "sched: $m $h $dom $mon $dow"
}

# next fire time for a schedule.  Prints "SHORT<TAB>ABS"  (or a plain string).
next_run() {
  local sched="$1" out
  case "$sched" in
    @reboot)            echo "at reboot"; return ;;
    @yearly|@annually)  set -- 0 0 1 1 '*' ;;
    @monthly)           set -- 0 0 1 '*' '*' ;;
    @weekly)            set -- 0 0 '*' '*' 0 ;;
    @daily|@midnight)   set -- 0 0 '*' '*' '*' ;;
    @hourly)            set -- 0 '*' '*' '*' '*' ;;
    @*)                 echo "$sched"; return ;;
    *)                  set -f; set -- $sched; set +f ;;
  esac
  [ -z "${5:-}" ] && { echo "?"; return; }
  if [ -n "$have_py" ]; then
    out=$("$have_py" -c "$PYNEXT" "$1" "$2" "$3" "$4" "$5" 2>/dev/null)
    case "$out" in ""|unknown|\?) ;; *) printf '%s' "$out"; return ;; esac
  fi
  human_sched "$1" "$2" "$3" "$4" "$5"
}

# analyse one raw cron line.  $1=source label  $2=1 if it has a user field  $3=line
analyze_line() {
  local src="$1" has_user="$2" line="$3"
  local runas cmd first tok sched nr_raw nr_short nr_abs nsuf

  line="${line#"${line%%[![:space:]]*}"}"           # ltrim
  case "$line" in ""|\#*) return ;; esac            # blank / comment
  case "$line" in PATH=*|SHELL=*|MAILTO=*|HOME=*|LOGNAME=*) return ;; esac

  # when does it next fire?
  if [ "${line:0:1}" = "@" ]; then
    sched=$(awk '{print $1}' <<<"$line")
  else
    sched=$(awk '{print $1,$2,$3,$4,$5}' <<<"$line")
  fi
  nr_raw=$(next_run "$sched")
  nr_short=${nr_raw%%$'\t'*}
  nr_abs=${nr_raw#*$'\t'}
  [ "$nr_abs" = "$nr_raw" ] && nr_abs=""            # no tab -> no absolute time

  # split off schedule fields to isolate USER (if any) + command
  if [ "${line:0:1}" = "@" ]; then                  # @reboot / @daily style
    if [ "$has_user" = "1" ]; then
      runas=$(awk '{print $2}' <<<"$line"); cmd=$(cut -d' ' -f3- <<<"$(tr -s ' ' <<<"$line")")
    else
      runas="$ME";                                   cmd=$(cut -d' ' -f2- <<<"$(tr -s ' ' <<<"$line")")
    fi
  else                                              # 5 time fields
    if [ "$has_user" = "1" ]; then
      runas=$(awk '{print $6}' <<<"$line"); cmd=$(cut -d' ' -f7- <<<"$(tr -s ' ' <<<"$line")")
    else
      runas="$ME";                                   cmd=$(cut -d' ' -f6- <<<"$(tr -s ' ' <<<"$line")")
    fi
  fi
  [ -z "$cmd" ] && return

  # highlight the raw entry (root jobs are the prize)
  nsuf="  ${GRN}next: ${nr_short}${RST}"
  [ -n "$nr_abs" ] && nsuf="$nsuf ${DIM}(${nr_abs})${RST}"
  if [ "$runas" = "root" ]; then
    printf '  %s[%s]%s runas=%s%s%s  %s%s\n' "$DIM" "$src" "$RST" "$RED" "$runas" "$RST" "$cmd" "$nsuf"
  else
    printf '  %s[%s]%s runas=%s  %s%s\n' "$DIM" "$src" "$RST" "$runas" "$cmd" "$nsuf"
  fi

  # 1) writability of every path-looking token, following into called/sourced files
  set -f
  for tok in $cmd; do examine "$tok" "$src runas=$runas next=$nr_short" 0; done
  set +f

  # 2) wildcard / argument injection
  case "$cmd" in
    *tar\ *\**|*rsync\ *\**|*7z*\**|*zip\ *\**|*chown\ *\**|*chmod\ *\**|*scp\ *\**|*wget\ *\**|*rar\ *\**)
      add_finding "HIGH" "$src" "wildcard (*) in job runas=$runas next=$nr_short: '$cmd' - possible wildcard/arg injection" ;;
  esac

  # 3) relative command name -> PATH hijack if any cron PATH dir is writable
  first=$(awk '{print $1}' <<<"$cmd")
  case "$first" in
    /*|./*|../*|"") ;;                               # explicit path -> not PATH-resolved
    cd|test|[|for|while|if|echo|true|false|:) ;;     # shell builtins - ignore
    *)
      local d
      IFS=':' read -ra _pd <<<"$CRON_PATH"
      for d in "${_pd[@]}"; do
        [ -n "$d" ] && [ -d "$d" ] && [ -w "$d" ] && \
          add_finding "HIGH" "$d" "job runas=$runas next=$nr_short calls '$first' via PATH; $d is writable - PATH hijack"
      done ;;
  esac
}

# read a crontab-style file line by line
scan_file() {
  local f="$1" has_user="$2" label="$3"
  [ -r "$f" ] || return
  while IFS= read -r l || [ -n "$l" ]; do
    analyze_line "${label:-$f}" "$has_user" "$l"
  done < "$f"
}

# =============================================================================
printf '%s\n' "${BLD}Scheduled-job enumeration${RST}  -  user: ${GRN}$ME${RST}  -  host: $(hostname 2>/dev/null)  -  $(date 2>/dev/null)"
printf '%s\n' "${DIM}$MYID${RST}"
printf '%s\n' "${DIM}cron PATH: $CRON_PATH${RST}"

# --- 1. RAW DUMP (your original two commands, expanded) ----------------------
sect "/etc/crontab"
cat /etc/crontab 2>/dev/null || echo "  (none / unreadable)"

sect "/etc/cron.d, /etc/cron.{hourly,daily,weekly,monthly}, /etc/anacrontab"
ls -la /etc/cron.* /etc/anacrontab 2>/dev/null || echo "  (none)"

sect "Per-user crontabs (/var/spool/cron)"
ls -la /var/spool/cron /var/spool/cron/crontabs 2>/dev/null
crontab -l 2>/dev/null | sed 's/^/  (me) /' || echo "  (no crontab for $ME)"

if command -v systemctl >/dev/null 2>&1; then
  sect "systemd timers"
  systemctl list-timers --all --no-pager 2>/dev/null
fi

# --- 2. WRITABLE LOCATIONS ---------------------------------------------------
if [ "$DO_FIND" = "1" ]; then
  sect "Writable directories ( find / -writable -type d )"
  WTMP=$(mktemp)
  find / -writable -type d 2>/dev/null > "$WTMP"
  printf '  total writable dirs: %s\n' "$(wc -l < "$WTMP")"
  printf '  %sinteresting (outside home/tmp/proc/sys/run/dev):%s\n' "$BLD" "$RST"
  grep -vE "^($HOME|/home/|/tmp|/var/tmp|/dev|/proc|/sys|/run)" "$WTMP" | sed 's/^/    /' | head -n 60
  rm -f "$WTMP"
else
  echo; echo "${DIM}(skipped  find /  writable sweep - --no-find)${RST}"
fi

# --- 3. ANALYSED JOBS (findings are collected while these print) -------------
sect "Parsed jobs (cross-referenced against your write access)"
scan_file /etc/crontab 1 "/etc/crontab"
[ -f /etc/anacrontab ] && scan_file /etc/anacrontab 0 "/etc/anacrontab"
for f in /etc/cron.d/*; do [ -f "$f" ] && scan_file "$f" 1 "cron.d/$(basename "$f")"; done
for f in /var/spool/cron/crontabs/* /var/spool/cron/*; do
  [ -f "$f" ] && scan_file "$f" 0 "spool/$(basename "$f")"
done
while IFS= read -r l; do analyze_line "crontab -l ($ME)" 0 "$l"; done < <(crontab -l 2>/dev/null)

# scripts dropped in the periodic run-parts dirs
for dir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
  [ -d "$dir" ] || continue
  for s in "$dir"/*; do
    [ -e "$s" ] || continue
    examine "$s" "run-parts $dir (root)" 0
  done
done

# systemd timer -> service ExecStart writability
if command -v systemctl >/dev/null 2>&1; then
  while read -r unit; do
    [ -z "$unit" ] && continue
    svc="${unit%.timer}.service"
    exec_line=$(systemctl cat "$svc" 2>/dev/null | grep -E '^\s*ExecStart=' | head -n1 | cut -d= -f2-)
    [ -z "$exec_line" ] && continue
    set -f
    for tok in $exec_line; do examine "$tok" "systemd timer $unit" 0; done
    set +f
  done < <(systemctl list-timers --all --no-pager 2>/dev/null | awk '/\.timer/{for(i=1;i<=NF;i++) if($i ~ /\.timer$/) print $i}')
fi

# --- SUMMARY ----------------------------------------------------------------
sect "FINDINGS"
if [ "${#FINDINGS[@]}" -eq 0 ]; then
  printf '  %sNo directly abusable scheduled jobs found for user %s.%s\n' "$GRN" "$ME" "$RST"
  printf '  %sStill worth a manual look at any root job above + pspy for jobs not in a crontab file.%s\n' "$DIM" "$RST"
else
  # de-dupe, CRIT first then HIGH
  printf '%s\n' "${FINDINGS[@]}" | sort -u | awk -F'|' '
    $1=="CRIT"{print}' | while IFS='|' read -r sev loc note; do
      printf '  %s[CRIT]%s %s\n         %s%s%s\n' "$RED" "$RST" "$loc" "$DIM" "$note" "$RST"
    done
  printf '%s\n' "${FINDINGS[@]}" | sort -u | awk -F'|' '
    $1=="HIGH"{print}' | while IFS='|' read -r sev loc note; do
      printf '  %s[HIGH]%s %s\n         %s%s%s\n' "$YEL" "$RST" "$loc" "$DIM" "$note" "$RST"
    done
fi
hr
printf '%sNext:%s writable script -> put a reverse shell / id>>file in it and wait for the job.\n' "$BLD" "$RST"
printf '      wildcard job     -> drop --checkpoint payload files in the target dir.\n'
printf '      PATH hijack      -> place a malicious binary named after the called command.\n'
printf '      seeing nothing?  -> run %spspy%s to catch jobs that are not in any crontab file.\n' "$BLD" "$RST"
