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
	Grant  bool
	Repos  []string
	Bridge bool
	Name   string
	Email  string
	// RefuseAuthor denies every git command and embeds no author value.
	RefuseAuthor bool
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
	grant, bridge := "0", "0"
	if opts.Grant {
		grant = "1"
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
	script = strings.ReplaceAll(script, "@@BRIDGE@@", bridge)
	script = strings.ReplaceAll(script, "@@NAME@@", opts.Name)
	script = strings.ReplaceAll(script, "@@EMAIL@@", opts.Email)
	script = strings.ReplaceAll(script, "@@REPOS@@", arms.String())
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
unset SSH_AUTH_SOCK http_proxy https_proxy HTTP_PROXY HTTPS_PROXY
real=/lgb/bin/git
log=/lgb/events/log
grant=@@GRANT@@
bridge=@@BRIDGE@@
author_name=@@NAME@@
author_email=@@EMAIL@@
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
vet() {
  folded=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]') || {
    echo "git ${sub} denied: repository is not allowlisted" >&2
    printf '%s\n' "deny git ${sub}" >> "$log"
    exit 1
  }
  case "$folded" in
    ""|file://*)
      return 0
      ;;
@@REPOS@@
    *://*|git@*)
      echo "git ${sub} denied: repository is not allowlisted" >&2
      printf '%s\n' "deny git ${sub}" >> "$log"
      exit 1
      ;;
  esac
  return 0
}
resolve_remote() {
  name=$1
  case "$name" in
    ""|-*)
      return
      ;;
    *://*|git@*|file://*|/*|./*|../*)
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
  if [ "$bridge" != "1" ] || [ ! -S /lgb/sock/github.sock ]; then
    echo "git denied: github proxy unavailable" >&2
    printf '%s\n' "deny git ${sub}" >> "$log"
    return 1
  fi
  /lgb/bin/ghbridge http /lgb/sock/github.sock > /tmp/gh.port &
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
    echo "git denied: github proxy unavailable" >&2
    printf '%s\n' "deny git ${sub}" >> "$log"
    return 1
  fi
  GHPORT=$p
  return 0
}
run() {
  if [ -n "$GHPORT" ]; then
    exec "$real" \
      -c user.name="$author_name" \
      -c user.email="$author_email" \
      -c commit.gpgsign=false \
      -c core.sshCommand=/bin/false \
      -c core.hooksPath=/dev/null \
      -c diff.external= \
      -c core.pager=cat \
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
    "$@"
}
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
  /lgb/bin/ghbridge push /lgb/sock/push.sock "$@"
  exit $?
fi
case "$sub" in
  clone|fetch|pull|ls-remote|remote)
    prev=
    seen_sub=
    for arg in "$@"; do
      if [ -n "$prev" ]; then
        prev=
        continue
      fi
      case "$arg" in
        -C|-c|--git-dir|--work-tree|--namespace|--super-prefix|--config-env|--exec-path|--upload-pack|--depth|--branch|-b|-o|--origin|--reference|--separate-git-dir|--template|--config|--server-option)
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
        *://*|git@*)
          vet "$arg"
          found_url=1
          ;;
        *)
          if [ -z "$pos" ]; then
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
