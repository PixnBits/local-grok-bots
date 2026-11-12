package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/github"
)

// gitWrapOpts is the git wrapper embedded in the jail. Name and email are
// checked before they are written into the script. A value that fails the
// charset check produces a wrapper that refuses every git command and does
// not contain that value.
type gitWrapOpts struct {
	Grant bool
	// Repos is the bot's effective allowlist. It is the only list embedded
	// in the wrapper. Policy-only names are not written into the jail.
	Repos []string
	// Hub is the github grant. It does not add repositories.
	Hub bool
	// Bridge is set when the credential socket is mounted.
	Bridge bool
	Name   string
	Email  string
	// RefuseAuthor denies every git command and embeds no author value.
	RefuseAuthor bool
}

const (
	// RepoNotAvailable is the only jail-visible denial for a repository
	// outside the bot's effective list. It does not say which list omitted it.
	RepoNotAvailable = "repository is not available to this bot"
	// GitHubGrantOff is the jail-visible text when the repository is on the
	// effective list and the github grant is off.
	GitHubGrantOff = "GitHub access is not enabled for this bot (github grant is off)"
	// GitHubBridgeDown is the jail-visible text when the repository is on the
	// effective list, the github grant is on, and the credential bridge is not running.
	GitHubBridgeDown = "GitHub access is unavailable right now (credential bridge not running)"
)

const (
	gitHubListBoth    = "the policy [github].repos ceiling and the bot's github_allow"
	gitHubListCeiling = "the policy [github].repos ceiling"
	gitHubListBot     = "the bot's github_allow"
)

// GitHubAllowlistWhere names the list that omits owner/repo.
// Both lists containing the repo returns an empty string. An empty name
// returns both lists. The allow decision stays the effective intersection.
func GitHubAllowlistWhere(policy, bot []string, owner, repo string) string {
	owner = strings.ToLower(strings.TrimSpace(owner))
	repo = strings.ToLower(strings.TrimSpace(repo))
	if owner == "" || repo == "" || strings.Contains(owner, "/") || strings.Contains(repo, "/") {
		return gitHubListBoth
	}
	inPol := repoListed(policy, owner, repo)
	inBot := repoListed(bot, owner, repo)
	switch {
	case inPol && inBot:
		return ""
	case !inPol && !inBot:
		return gitHubListBoth
	case !inPol:
		return gitHubListCeiling
	default:
		return gitHubListBot
	}
}

func repoListed(list []string, owner, repo string) bool {
	want := owner + "/" + repo
	for _, raw := range list {
		name, err := github.NormalizeRepo(raw)
		if err != nil {
			continue
		}
		if name == want {
			return true
		}
	}
	return false
}

func gitWrap(opts gitWrapOpts) string {
	if opts.RefuseAuthor {
		return denyAuthorScript
	}
	if opts.Name == "" {
		opts.Name = "local-grok-bots"
	}
	if opts.Email == "" {
		opts.Email = "bot@localhost"
	}
	if !authorEmbeddable(opts.Name, opts.Email) {
		return denyAuthorScript
	}
	grant, hub, bridge := "0", "0", "0"
	if opts.Grant {
		grant = "1"
	}
	if opts.Hub {
		hub = "1"
	}
	if opts.Bridge {
		bridge = "1"
	}
	var arms strings.Builder
	for _, raw := range opts.Repos {
		repo, err := github.NormalizeRepo(raw)
		if err != nil {
			continue
		}
		fmt.Fprintf(&arms, "    https://github.com/%s|https://github.com/%s.git|https://github.com/%s/|https://github.com/%s.git/)\n      need_bridge=1\n      return 0\n      ;;\n", repo, repo, repo, repo)
	}
	script := gitWrapScript
	script = strings.ReplaceAll(script, "@@GRANT@@", grant)
	script = strings.ReplaceAll(script, "@@HUB@@", hub)
	script = strings.ReplaceAll(script, "@@BRIDGE@@", bridge)
	script = strings.ReplaceAll(script, "@@NAME@@", opts.Name)
	script = strings.ReplaceAll(script, "@@EMAIL@@", opts.Email)
	script = strings.ReplaceAll(script, "@@REPOS@@", arms.String())
	script = strings.ReplaceAll(script, "@@DENY_REPO@@", RepoNotAvailable)
	script = strings.ReplaceAll(script, "@@DENY_GRANT@@", GitHubGrantOff)
	script = strings.ReplaceAll(script, "@@DENY_BRIDGE@@", GitHubBridgeDown)
	return script
}

const denyAuthorScript = "#!/bin/sh\n" +
	"echo \"git denied: invalid author\" >&2\n" +
	"printf '%s\\n' \"deny git author\" >> /lgb/events/log\n" +
	"exit 1\n"

func authorEmbeddable(name, email string) bool {
	if !github.ValidAuthorName(name) {
		return false
	}
	if email == "" || len(email) > 254 || strings.ContainsAny(email, " \t'\"\\$`;|&<>(){}[]!*?#\r\n\x00") {
		return false
	}
	local, domain, ok := strings.Cut(email, "@")
	if !ok || local == "" || domain == "" || strings.Contains(domain, "@") {
		return false
	}
	return true
}

const gitWrapScript = `#!/bin/sh
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_SYSTEM=/dev/null
export GIT_CONFIG_NOSYSTEM=1
unset SSH_AUTH_SOCK http_proxy https_proxy HTTP_PROXY HTTPS_PROXY NO_PROXY no_proxy
real=/lgb/bin/git
log=/lgb/events/log
nl='
'
grant=@@GRANT@@
hub=@@HUB@@
bridge=@@BRIDGE@@
author_name=@@NAME@@
author_email=@@EMAIL@@
if [ "$bridge" = 1 ]; then
  export GIT_ALLOW_PROTOCOL=https:ssh:http
else
  export GIT_ALLOW_PROTOCOL=https:ssh
fi
allow_file=0
pfile=never
vet_base=$PWD
sub=
prev=
for arg in "$@"; do
  if [ -n "$prev" ]; then
    prev=
    continue
  fi
  case "$arg" in
    -C|-c|--git-dir|--work-tree|--namespace|--super-prefix|--config-env|--exec-path)
      prev=1
      ;;
    --git-dir=*|--work-tree=*|--namespace=*|--super-prefix=*|--config-env=*|--exec-path=*)
      ;;
    --)
      ;;
    -*)
      ;;
    *)
      sub=$arg
      break
      ;;
  esac
done
GHPORT=
need_bridge=0
found_url=0
pos=
deny_allow() {
  case "$1" in
    *"$nl"*)
      printf '%s\n' "deny git ${sub}" >> "$log"
      ;;
    *)
      printf '%s\n' "deny github allowlist $1" >> "$log"
      ;;
  esac
}
say_deny() {
  echo "git ${sub} denied: @@DENY_REPO@@" >&2
  deny_allow "$1"
  exit 1
}
say_file() {
  echo "git ${sub} denied: local path is outside the workspace" >&2
  printf '%s\n' "deny git ${sub}" >> "$log"
  exit 1
}
say_config() {
  echo "git ${sub} denied: configuration is not allowed" >&2
  printf '%s\n' "deny git ${sub}" >> "$log"
  exit 1
}
# Refuse a config assignment whose key rewrites URLs.
url_assign() {
  folded=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]') || say_config
  key=${folded%%=*}
  case "$key" in
    url.*) say_config ;;
  esac
}
# Record -C as the base for a relative path, and refuse url rewrites.
scan_global() {
  prev=
  base=$PWD
  for arg in "$@"; do
    if [ -n "$prev" ]; then
      case "$prev" in
        C)
          case "$arg" in
            /*) base=$arg ;;
            *) base=$base/$arg ;;
          esac
          ;;
        c|env)
          url_assign "$arg"
          ;;
      esac
      prev=
      continue
    fi
    case "$arg" in
      -C)
        prev=C
        ;;
      -c)
        prev=c
        ;;
      -c*)
        url_assign "${arg#-c}"
        ;;
      --config-env)
        prev=env
        ;;
      --config-env=*)
        url_assign "${arg#--config-env=}"
        ;;
      --git-dir|--work-tree|--namespace|--super-prefix|--exec-path)
        prev=x
        ;;
      --)
        ;;
      -*)
        ;;
      *)
        break
        ;;
    esac
  done
  vet_base=$base
}
clean_abs() {
  p=$1
  case "$p" in
    /*) ;;
    *) return 1 ;;
  esac
  out=
  rest=$p
  while [ -n "$rest" ]; do
    rest=${rest#/}
    seg=${rest%%/*}
    if [ "$rest" = "$seg" ]; then
      rest=
    else
      rest=${rest#*/}
    fi
    if [ -z "$seg" ] || [ "$seg" = "." ]; then
      continue
    fi
    if [ "$seg" = ".." ]; then
      return 1
    fi
    out=$out/$seg
  done
  if [ -z "$out" ]; then
    out=/
  fi
  printf '%s' "$out"
}
inside_work() {
  case "$1" in
    /work|/work/*) return 0 ;;
  esac
  return 1
}
phys_inside() {
  target=$1
  depth=$2
  if [ -z "$depth" ]; then
    depth=0
  fi
  if [ "$depth" -gt 8 ]; then
    return 1
  fi
  if [ ! -d /work ]; then
    return 0
  fi
  if [ -L "$target" ]; then
    dest=$(readlink "$target") || return 1
    case "$dest" in
      /*) ;;
      *) dest=$(dirname "$target")/$dest ;;
    esac
    cleaned=$(clean_abs "$dest") || return 1
    inside_work "$cleaned" || return 1
    phys_inside "$cleaned" $((depth + 1))
    return $?
  fi
  dir=$target
  if [ ! -d "$target" ]; then
    if [ -e "$target" ]; then
      dir=$(dirname "$target")
    else
      while [ ! -d "$dir" ] && [ "$dir" != / ]; do
        dir=$(dirname "$dir")
      done
    fi
  fi
  phys=$(cd "$dir" && pwd -P) || return 1
  inside_work "$phys" || return 1
  return 0
}
# Percent-decode one path. Git decodes a file URL before opening it.
# A short or non-hex escape, a NUL, or a newline is refused.
pct_decode() {
  s=$1
  out=
  while [ -n "$s" ]; do
    c=${s%"${s#?}"}
    rest=${s#?}
    if [ "$c" = "%" ]; then
      h1=${rest%"${rest#?}"}
      rest=${rest#?}
      h2=${rest%"${rest#?}"}
      rest=${rest#?}
      hex=$h1$h2
      case "$hex" in
        [0-9A-Fa-f][0-9A-Fa-f]) ;;
        *) return 1 ;;
      esac
      dec=$((0x$hex)) || return 1
      if [ "$dec" -eq 0 ] || [ "$dec" -eq 10 ] || [ "$dec" -eq 13 ]; then
        return 1
      fi
      oct=$(printf '%03o' "$dec")
      ch=$(printf "\\$oct")
      out=$out$ch
      s=$rest
    else
      out=$out$c
      s=$rest
    fi
  done
  printf '%s' "$out"
}
# Refuse a ".." path segment. This runs on the decoded path.
reject_dotdot() {
  rest=$1
  while [ -n "$rest" ]; do
    rest=${rest#/}
    seg=${rest%%/*}
    if [ "$rest" = "$seg" ]; then
      rest=
    else
      rest=${rest#*/}
    fi
    if [ "$seg" = ".." ]; then
      return 1
    fi
  done
  return 0
}
file_url_path() {
  raw=$1
  prefix=$(printf '%s' "$raw" | cut -c 1-7 | tr '[:upper:]' '[:lower:]') || return 1
  if [ "$prefix" != "file://" ]; then
    return 1
  fi
  rest=$(printf '%s' "$raw" | cut -c 8-) || return 1
  case "$rest" in
    /*)
      path=$rest
      ;;
    *)
      case "$rest" in
        */*) ;;
        *) return 1 ;;
      esac
      host=$(printf '%s' "${rest%%/*}" | tr '[:upper:]' '[:lower:]') || return 1
      if [ "$host" != "localhost" ]; then
        return 1
      fi
      path="/${rest#*/}"
      ;;
  esac
  decoded=$(pct_decode "$path") || return 1
  reject_dotdot "$decoded" || return 1
  printf '%s' "$decoded"
}
accept_local() {
  cleaned=$(clean_abs "$1") || say_file
  inside_work "$cleaned" || say_file
  phys_inside "$cleaned" || say_file
  allow_file=1
}
scan_urls() {
  for arg in "$@"; do
    prefix=$(printf '%s' "$arg" | cut -c 1-7 | tr '[:upper:]' '[:lower:]') || say_file
    if [ "$prefix" = "file://" ]; then
      vet "$arg"
    fi
  done
}
vet() {
  case "$1" in
    *"$nl"*)
      say_deny "$1"
      ;;
  esac
  folded=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]') || say_deny "$1"
  case "$folded" in
    "")
      return 0
      ;;
    file://*)
      pth=$(file_url_path "$1") || say_file
      accept_local "$pth"
      return 0
      ;;
@@REPOS@@
    *://*|git@*)
      say_deny "$1"
      ;;
  esac
  case "$1" in
    /*)
      accept_local "$1"
      return 0
      ;;
    ./*|../*|..|*/..|*/../*|*/*|.)
      vet_local "$1"
      return 0
      ;;
  esac
  return 0
}
vet_local() {
  case "$1" in
    /*)
      accept_local "$1"
      ;;
    *)
      accept_local "$vet_base/$1"
      ;;
  esac
}
resolve_remote() {
  name=$1
  case "$name" in
    ""|-*)
      return
      ;;
    *://*|git@*|file://*|/*|./*|../*|..|*/..|*/../*|*/*|.)
      vet "$name"
      found_url=1
      return
      ;;
  esac
  u=$("$real" remote get-url "$name" 2>/dev/null) || return
  vet "$u"
}
ensure_bridge() {
  if [ -n "$GHPORT" ]; then
    return 0
  fi
  if [ "$hub" != "1" ]; then
    echo "git denied: @@DENY_GRANT@@" >&2
    printf '%s\n' "deny git ${sub}" >> "$log"
    return 1
  fi
  if [ "$bridge" != "1" ] || [ ! -S /lgb/sock/github.sock ]; then
    echo "git denied: @@DENY_BRIDGE@@" >&2
    printf '%s\n' "deny git ${sub}" >> "$log"
    return 1
  fi
  /lgb/bin/ghbridge http /lgb/sock/github.sock </dev/null >/tmp/gh.port 2>/dev/null &
  i=0
  p=
  while [ "$i" -lt 100000 ]; do
    if [ -s /tmp/gh.port ]; then
      p=$(tr -cd 0-9 < /tmp/gh.port)
    fi
    if [ -n "$p" ]; then
      break
    fi
    i=$((i + 1))
  done
  if [ -z "$p" ]; then
    echo "git denied: @@DENY_BRIDGE@@" >&2
    printf '%s\n' "deny git ${sub}" >> "$log"
    return 1
  fi
  GHPORT=$p
  return 0
}
run() {
  if [ "$allow_file" = 1 ]; then
    GIT_ALLOW_PROTOCOL="${GIT_ALLOW_PROTOCOL}:file"
    export GIT_ALLOW_PROTOCOL
    pfile=always
  else
    pfile=never
  fi
  if [ "$sub" = diff ] || [ "$sub" = log ] || [ "$sub" = show ]; then
    if [ -x /bin/bash ]; then
      exec /bin/bash --norc --noprofile -c '
real=$1
name=$2
email=$3
port=$4
sub=$5
shift 5
args=()
prev=
ins=0
for arg in "$@"; do
  if [ -n "$prev" ]; then
    args+=("$arg")
    prev=
    continue
  fi
  case "$arg" in
    -C|-c|--git-dir|--work-tree|--namespace|--super-prefix|--config-env|--exec-path)
      args+=("$arg")
      prev=1
      continue
      ;;
    --git-dir=*|--work-tree=*|--namespace=*|--super-prefix=*|--config-env=*|--exec-path=*|--upload-pack=*)
      args+=("$arg")
      continue
      ;;
    -*)
      args+=("$arg")
      continue
      ;;
  esac
  args+=("$arg")
  if [ "$ins" = 0 ]; then
    args+=(--no-ext-diff --no-textconv)
    ins=1
  fi
done
cargs=(-c user.name="$name" -c user.email="$email" -c commit.gpgsign=false -c core.sshCommand=/bin/false -c core.hooksPath=/dev/null -c protocol.file.allow=never -c diff.external= -c core.pager=cat -c core.fsmonitor= -c core.fsmonitorHookVersion=)
if [ -n "$port" ]; then
  exec "$real" "${cargs[@]}" -c http.proxy= -c "url.http://127.0.0.1:${port}/github/.insteadOf=https://github.com/" -c "url.http://127.0.0.1:${port}/api/.insteadOf=https://api.github.com/" "${args[@]}"
fi
exec "$real" "${cargs[@]}" "${args[@]}"
' bash "$real" "$author_name" "$author_email" "$GHPORT" "$sub" "$@"
    fi
  fi
  if [ -n "$GHPORT" ]; then
    exec "$real" \
      -c user.name="$author_name" \
      -c user.email="$author_email" \
      -c commit.gpgsign=false \
      -c core.sshCommand=/bin/false \
      -c core.hooksPath=/dev/null \
      -c diff.external= \
      -c core.pager=cat \
      -c core.fsmonitor= \
      -c core.fsmonitorHookVersion= \
      -c protocol.file.allow="$pfile" \
      -c http.proxy= \
      -c "url.http://127.0.0.1:${GHPORT}/github/.insteadOf=https://github.com/" \
      -c "url.http://127.0.0.1:${GHPORT}/api/.insteadOf=https://api.github.com/" \
      "$@"
  fi
  exec "$real" \
    -c user.name="$author_name" \
    -c user.email="$author_email" \
    -c commit.gpgsign=false \
    -c core.sshCommand=/bin/false \
    -c core.hooksPath=/dev/null \
    -c diff.external= \
    -c core.pager=cat \
    -c core.fsmonitor= \
    -c core.fsmonitorHookVersion= \
    -c protocol.file.allow="$pfile" \
    "$@"
}
scan_global "$@"
scan_urls "$@"
case "$sub" in
  ""|status|diff|log|show|rev-parse|blame|ls-files|grep|version|help|describe|name-rev|cat-file|shortlog|var)
    run "$@"
    ;;
esac
if [ "$grant" != "1" ]; then
  echo "git ${sub} denied: missing git grant" >&2
  printf '%s\n' "deny git ${sub}" >> "$log"
  exit 1
fi
if [ "$sub" = "push" ]; then
  if [ ! -x /lgb/bin/ghbridge ] || [ ! -S /lgb/sock/push.sock ]; then
    echo "git push denied: not sent" >&2
    printf '%s\n' "deny git push" >> "$log"
    exit 1
  fi
  case "$PWD" in
    /work)
      rel=.
      ;;
    /work/*)
      rel=${PWD#/work/}
      ;;
    *)
      echo "git push denied: repository not found in workspace" >&2
      printf '%s\n' "deny git push" >> "$log"
      exit 1
      ;;
  esac
  /lgb/bin/ghbridge push /lgb/sock/push.sock "$rel" "$@"
  exit $?
fi
case "$sub" in
  clone|fetch|pull|ls-remote|remote|submodule)
    prev=
    seen_sub=
    for arg in "$@"; do
      if [ -n "$prev" ]; then
        if [ "$prev" = cfg ]; then
          url_assign "$arg"
        fi
        prev=
        continue
      fi
      case "$arg" in
        --recurse-submodules|--recurse-submodules=*|--recursive|--shallow-submodules)
          if [ "$sub" = clone ] || [ "$sub" = fetch ] || [ "$sub" = pull ]; then
            echo "git ${sub} denied: submodule path is outside the workspace" >&2
            printf '%s\n' "deny git ${sub}" >> "$log"
            exit 1
          fi
          continue
          ;;
        -c|--config|--config-env)
          prev=cfg
          continue
          ;;
        -c*)
          url_assign "${arg#-c}"
          continue
          ;;
        --config=*)
          url_assign "${arg#--config=}"
          continue
          ;;
        --config-env=*)
          url_assign "${arg#--config-env=}"
          continue
          ;;
        -C|--git-dir|--work-tree|--namespace|--super-prefix|--exec-path|--upload-pack|--depth|--branch|-b|-o|--origin|--reference|--separate-git-dir|--template|--server-option)
          prev=1
          continue
          ;;
        --)
          continue
          ;;
        -*)
          continue
          ;;
      esac
      if [ -z "$seen_sub" ]; then
        seen_sub=1
        continue
      fi
      case "$arg" in
        *://*|git@*|file://*|/*|./*|../*|..|*/..|*/../*|*/*|.)
          vet "$arg"
          found_url=1
          ;;
        *)
          if [ "$sub" = clone ] && [ "$found_url" = "0" ]; then
            vet_local "$arg"
            found_url=1
          elif [ -z "$pos" ]; then
            pos=$arg
          fi
          ;;
      esac
    done
    if [ "$found_url" = "0" ]; then
      if [ -n "$pos" ]; then
        resolve_remote "$pos"
      elif [ "$sub" = "fetch" ] || [ "$sub" = "pull" ]; then
        for r in $("$real" remote 2>/dev/null); do
          resolve_remote "$r"
        done
      fi
    fi
    if [ "$need_bridge" = "1" ]; then
      ensure_bridge || exit 1
    fi
    ;;
esac
printf '%s\n' "use git ${sub}" >> "$log"
run "$@"
`

func sshWrap(grant bool, hosts []string) string {
	g := 0
	if grant {
		g = 1
	}
	var arms strings.Builder
	if len(hosts) == 0 {
		arms.WriteString("    *) ok=0 ;;\n")
	} else {
		for _, h := range hosts {
			fmt.Fprintf(&arms, "    %s) ok=1 ;;\n", h)
		}
	}
	return fmt.Sprintf(`#!/bin/sh
unset SSH_AUTH_SOCK
real=/lgb/bin/ssh
log=/lgb/events/log
grant=%d
host=
prev=
for arg in "$@"; do
  case "$arg" in
    *IdentityAgent*|*IdentityFile*|*IdentitiesOnly*|*ProxyCommand*|*ProxyJump*|*PKCS11*|*CertificateFile*)
      echo "ssh option denied" >&2
      printf '%%s\n' "deny ssh option" >> "$log"
      exit 1
      ;;
  esac
done
prev=
for arg in "$@"; do
  if [ -n "$prev" ]; then
    prev=
    continue
  fi
  case "$arg" in
    -A|-F|-i|-J)
      echo "ssh option denied" >&2
      printf '%%s\n' "deny ssh option" >> "$log"
      exit 1
      ;;
    -b|-c|-D|-E|-e|-I|-L|-l|-m|-O|-o|-p|-Q|-R|-S|-W|-w)
      prev=1
      ;;
    -*)
      ;;
    *)
      host=$arg
      break
      ;;
  esac
done
case "$host" in
  *@*) host=${host##*@} ;;
esac
host=$(printf '%%s' "$host" | tr -cd 'A-Za-z0-9._-')
if [ "$grant" != "1" ]; then
  echo "ssh denied: missing ssh grant" >&2
  printf '%%s\n' "deny ssh ${host:-unknown}" >> "$log"
  exit 1
fi
if [ ! -f /lgb/id_ed25519 ]; then
  echo "ssh denied: no dedicated key" >&2
  printf '%%s\n' "deny ssh ${host:-unknown}" >> "$log"
  exit 1
fi
ok=0
case "$host" in
%s
esac
if [ "$ok" != "1" ]; then
  echo "ssh denied: ${host} is not allowlisted" >&2
  printf '%%s\n' "deny ssh ${host:-unknown}" >> "$log"
  exit 1
fi
exec "$real" "$@" \
  -F /dev/null \
  -o IdentitiesOnly=yes \
  -o IdentityAgent=none \
  -o IdentityFile=/lgb/id_ed25519 \
  -o StrictHostKeyChecking=accept-new \
  -o UserKnownHostsFile=/tmp/known_hosts \
  -o BatchMode=yes
`, g, arms.String())
}

func pkgWrap(real string) string {
	return fmt.Sprintf(`#!/bin/sh
log=/lgb/events/log
hit=0
for arg in "$@"; do
  case "$arg" in
    install|upgrade|remove|dist-upgrade|purge|autoremove|add|del|delete|-S|-U|-R|-Syu|-Syyu)
      hit=1
      ;;
  esac
done
if [ "$hit" = "1" ]; then
  printf '%%s\n' pkg >> "$log"
fi
exec %s "$@"
`, real)
}

// EnsureKey returns an ed25519 key at path, creating it when missing.
// The key belongs to the daemon. It is not the user's agent.
func EnsureKey(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("ssh key path required")
	}
	if st, err := os.Stat(path); err == nil && !st.IsDir() {
		return path, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-f", path, "-N", "", "-q")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("ssh-keygen: %v %s", err, out)
	}
	return path, nil
}
