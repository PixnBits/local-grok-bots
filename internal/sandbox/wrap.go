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
# Drop config that arrived in the environment, then pin the files git may read.
unset GIT_CONFIG GIT_CONFIG_PARAMETERS GIT_CONFIG_COUNT
cfg_names=$(env | while IFS= read -r cfg_line; do
  case "$cfg_line" in
    GIT_CONFIG*=*)
      printf '%s\n' "${cfg_line%%=*}"
      ;;
  esac
done)
for cfg_name in $cfg_names; do
  case "$cfg_name" in
    GIT_CONFIG_GLOBAL|GIT_CONFIG_SYSTEM|GIT_CONFIG_NOSYSTEM)
      ;;
    *)
      unset "$cfg_name"
      ;;
  esac
done
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_SYSTEM=/dev/null
export GIT_CONFIG_NOSYSTEM=1
unset SSH_AUTH_SOCK http_proxy https_proxy HTTP_PROXY HTTPS_PROXY NO_PROXY no_proxy
# Drop an inherited transport list and command paths. run sets the list for this command.
unset GIT_ALLOW_PROTOCOL
unset GIT_SSH GIT_SSH_COMMAND GIT_SSH_VARIANT GIT_PROXY_COMMAND GIT_EXEC_PATH GIT_TEMPLATE_DIR
unset GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR GIT_NAMESPACE GIT_OBJECT_DIRECTORY GIT_INDEX_FILE GIT_CEILING_DIRECTORIES GIT_ASKPASS GIT_EXTERNAL_DIFF GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_PROTOCOL
unset GIT_EDITOR VISUAL EDITOR GIT_SEQUENCE_EDITOR
export GIT_NO_LAZY_FETCH=1
real=/lgb/bin/git
log=/lgb/events/log
nl='
'
grant=@@GRANT@@
hub=@@HUB@@
bridge=@@BRIDGE@@
author_name=@@NAME@@
author_email=@@EMAIL@@
allow_file=0
pfile=never
vet_base=$PWD
saw_repo_opt=
# Quoted --git-dir and --work-tree words. Expanded when config is read.
gitdir_args=
sub=
prev=
for arg in "$@"; do
  if [ -n "$prev" ]; then
    prev=
    continue
  fi
  case "$arg" in
    -C|-c|--git-dir|--work-tree|--namespace|--super-prefix|--config-env|--exec-path|--config|--attr-source)
      prev=1
      ;;
    --git-dir=*|--work-tree=*|--namespace=*|--super-prefix=*|--config-env=*|--exec-path=*|--config=*|--attr-source=*)
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
remote_sub=
remote_names=
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
say_config_key() {
  sk_key=$(printf '%s' "$1" | tr -cd 'A-Za-z0-9._*-')
  sk_key=$(printf '%s' "$sk_key" | cut -c 1-100)
  echo "git ${sub} denied: configuration is not allowed: ${sk_key}" >&2
  printf '%s\n' "deny git ${sub}" >> "$log"
  exit 1
}
say_option() {
  echo "git ${sub} denied: option is not allowed" >&2
  printf '%s\n' "deny git ${sub}" >> "$log"
  exit 1
}
# These options name a command. A shorter spelling is refused as well.
# --exec-path is a different option and does not match.
refuse_command_opt() {
  case "$1" in
    --*) ;;
    *) return 1 ;;
  esac
  body=${1#--}
  name=${body%%=*}
  if [ -z "$name" ]; then
    return 1
  fi
  case "$sub" in
    clone|fetch|pull|ls-remote)
      case "upload-pack" in
        "$name"*) say_option ;;
      esac
      case "exec" in
        "$name"*) say_option ;;
      esac
      ;;
    push)
      case "receive-pack" in
        "$name"*) say_option ;;
      esac
      case "exec" in
        "$name"*) say_option ;;
      esac
      ;;
  esac
  # fetch --multiple is one remote list. A shorter spelling is the same option.
  if [ "$sub" = fetch ]; then
    case "multiple" in
      "$name"*) say_option ;;
    esac
  fi
  return 1
}
# A short spelling of the submodule options is refused as well.
refuse_submodule_opt() {
  case "$1" in
    --*) ;;
    *) return 1 ;;
  esac
  case "$sub" in
    clone|fetch|pull) ;;
    *) return 1 ;;
  esac
  body=${1#--}
  name=${body%%=*}
  if [ -z "$name" ]; then
    return 1
  fi
  case "recurse-submodules" in
    "$name"*)
      echo "git ${sub} denied: submodule path is outside the workspace" >&2
      printf '%s\n' "deny git ${sub}" >> "$log"
      exit 1
      ;;
  esac
  case "recursive" in
    "$name"*)
      echo "git ${sub} denied: submodule path is outside the workspace" >&2
      printf '%s\n' "deny git ${sub}" >> "$log"
      exit 1
      ;;
  esac
  case "shallow-submodules" in
    "$name"*)
      echo "git ${sub} denied: submodule path is outside the workspace" >&2
      printf '%s\n' "deny git ${sub}" >> "$log"
      exit 1
      ;;
  esac
  return 1
}
# Refuse a config assignment that can retarget a remote or name a command.
url_assign() {
  folded=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]') || say_config
  key=${folded%%=*}
  case "$key" in
    protocol.*|core.*|remote.*|url.*|include*|includeif.*|credential.*|http.*|ssh.*|filter.*|alias.*)
      say_config_key "$key"
      ;;
  esac
}
# Record -C as the base for a relative path, and refuse url rewrites.
scan_global() {
  for arg in "$@"; do
    case "$arg" in
      --attr-source|--attr-source=*)
        say_option
        ;;
    esac
  done
  prev=
  base=$PWD
  gitdir_args=
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
        repo)
          gitdir_args="$gitdir_args $(quote "$arg")"
          ;;
      esac
      prev=
      continue
    fi
    case "$arg" in
      --exec-path|--exec-path=*)
        say_option
        ;;
      -C)
        prev=C
        ;;
      -c)
        prev=c
        ;;
      -c*)
        url_assign "${arg#-c}"
        ;;
      --config|--config-env)
        prev=c
        ;;
      --config=*|--config-env=*)
        url_assign "${arg#*=}"
        ;;
      --git-dir|--work-tree)
        saw_repo_opt=1
        gitdir_args="$gitdir_args $(quote "$arg")"
        prev=repo
        ;;
      --git-dir=*|--work-tree=*)
        saw_repo_opt=1
        gitdir_args="$gitdir_args $(quote "$arg")"
        ;;
      --namespace|--super-prefix)
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
# Allowed repository keys. Used by the effective-config scan and by config_guard.
config_key_allowed() {
  ck_key=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]') || return 1
  case "$ck_key" in
    # Repository format and filesystem probes written by init and clone.
    core.repositoryformatversion|core.filemode|core.bare|core.logallrefupdates|core.ignorecase|core.precomposeunicode|core.symlinks)
      ;;
    # Relative worktree path; the caller still checks that it resolves inside the workspace.
    core.worktree)
      ;;
    # Upstream tracking written by clone, checkout -b, and branch --set-upstream-to.
    branch.*.remote|branch.*.merge|branch.*.rebase|branch.*.description|branch.*.pushremote)
      ;;
    # Remote definition. The url is checked again when a command uses it.
    remote.*.url|remote.*.fetch)
      ;;
    # Written by clone --no-tags and clone --mirror.
    remote.*.tagopt)
      ;;
    # Written by clone --mirror. It marks a mirror remote and does not name a command.
    remote.*.mirror)
      ;;
    # Written by init --object-format=sha256.
    extensions.objectformat)
      ;;
    # Author identity. Refusing these would lock the repository after git config user.name.
    user.name|user.email)
      ;;
    # Written by submodule add. Submodule paths and urls are checked separately.
    submodule.*.url|submodule.*.active|submodule.active)
      ;;
    # Line-ending settings. They do not name a command or a path.
    core.autocrlf|core.eol|core.safecrlf)
      ;;
    # Whitespace and path display. They do not name a command or a path.
    core.whitespace|core.abbrev|core.quotepath|core.longpaths)
      ;;
    # Sparse-checkout. extensions.worktreeConfig is written by sparse-checkout init.
    core.sparsecheckout|core.sparsecheckoutcone|index.sparse|extensions.worktreeconfig)
      ;;
    # Untracked cache is an index bit. It does not name a command.
    core.untrackedcache)
      ;;
    # Pull defaults. They do not name a command or a path.
    pull.rebase|pull.ff)
      ;;
    # Init default branch name. It does not name a command or a path.
    init.defaultbranch)
      ;;
    # Push defaults. They do not name a command or a path.
    push.default|push.autosetupremote|push.followtags)
      ;;
    # Fetch defaults. They do not name a command or a path.
    fetch.prune|fetch.prunetags|fetch.parallel)
      ;;
    # Merge defaults. They do not name a command or a path.
    merge.ff|merge.conflictstyle)
      ;;
    # Rebase defaults. They do not name a command or a path.
    rebase.autostash|rebase.autosquash)
      ;;
    # Status display. They do not name a command or a path.
    status.showuntrackedfiles|status.branch|status.short)
      ;;
    # Log date format. It does not name a command or a path.
    log.date)
      ;;
    # Diff algorithm name. It does not name a command or a path.
    diff.algorithm)
      ;;
    # Rerere toggle. It does not name a command or a path.
    rerere.enabled)
      ;;
    # Branch tracking defaults. They do not name a command or a path.
    branch.autosetupmerge|branch.autosetuprebase)
      ;;
    # Color settings. They do not name a command or a path.
    color.*)
      ;;
    # Advice settings. They do not name a command or a path.
    advice.*)
      ;;
    # gc.auto is a threshold. It does not name a command or a path.
    gc.auto)
      ;;
    # Tag sort key. It does not name a command or a path.
    tag.sort)
      ;;
    *)
      return 1
      ;;
  esac
  return 0
}
# core.worktree is allowed only when the value is relative and resolves inside /work.
check_core_worktree() {
  wt_tab=$(printf '\t')
  wt_lines=$(
    eval "set -- $gitdir_args"
    "$real" -C "$vet_base" "$@" \
      -c core.hooksPath=/dev/null \
      -c core.fsmonitor= \
      -c core.sshCommand=/bin/false \
      -c protocol.allow=never \
      -c safe.directory='*' \
      config --includes --show-origin --get-all core.worktree 2>/dev/null
  ) || say_config_key "core.worktree"
  if [ -z "$wt_lines" ]; then
    say_config_key "core.worktree"
  fi
  wt_rest=$wt_lines
  while [ -n "$wt_rest" ]; do
    case "$wt_rest" in
      *"$nl"*)
        wt_line=${wt_rest%%"$nl"*}
        wt_rest=${wt_rest#*"$nl"}
        ;;
      *)
        wt_line=$wt_rest
        wt_rest=
        ;;
    esac
    if [ -z "$wt_line" ]; then
      continue
    fi
    case "$wt_line" in
      *"$wt_tab"*)
        wt_origin=${wt_line%%"$wt_tab"*}
        wt_val=${wt_line#*"$wt_tab"}
        ;;
      *)
        say_config_key "core.worktree"
        ;;
    esac
    case "$wt_origin" in
      file:*)
        wt_file=${wt_origin#file:}
        ;;
      *)
        say_config_key "core.worktree"
        ;;
    esac
    case "$wt_val" in
      ""|/*)
        say_config_key "core.worktree"
        ;;
    esac
    case "$wt_file" in
      /*)
        wt_abs=$wt_file
        ;;
      *)
        wt_abs=$vet_base/$wt_file
        ;;
    esac
    wt_gitdir=$(dirname "$wt_abs")
    wt_resolved=$(cd -- "$wt_gitdir/$wt_val" && pwd -P) || say_config_key "core.worktree"
    inside_work "$wt_resolved" || say_config_key "core.worktree"
  done
}
# git config skips the allowlist read so a refused key can be removed.
# --file/-f/--blob are refused in every form; the jail does not need them.
config_guard() {
  cg_seen=
  cg_prev=
  cg_dd=
  cg_action=
  cg_subcmd=
  cg_key=
  cg_npos=0
  for arg in "$@"; do
    if [ -z "$cg_seen" ]; then
      if [ -n "$cg_prev" ]; then
        cg_prev=
        continue
      fi
      case "$arg" in
        -C|-c|--git-dir|--work-tree|--namespace|--super-prefix|--config-env|--exec-path|--config|--attr-source)
          cg_prev=1
          continue
          ;;
        --git-dir=*|--work-tree=*|--namespace=*|--super-prefix=*|--config-env=*|--exec-path=*|--config=*|--attr-source=*|-c*)
          continue
          ;;
        --)
          continue
          ;;
        -*)
          continue
          ;;
        *)
          cg_seen=1
          continue
          ;;
      esac
    fi
    if [ -n "$cg_dd" ]; then
      if [ -z "$cg_subcmd" ] && [ "$cg_npos" -eq 0 ]; then
        case "$arg" in
          get|list)
            cg_subcmd=$arg
            cg_action=read
            continue
            ;;
          unset|remove-section)
            cg_subcmd=$arg
            cg_action=unset
            continue
            ;;
          set|add)
            cg_subcmd=$arg
            cg_action=write
            continue
            ;;
          edit|rename-section)
            say_option
            ;;
        esac
      fi
      cg_npos=$((cg_npos + 1))
      if [ -z "$cg_key" ]; then
        cg_key=$arg
      fi
      continue
    fi
    if [ -n "$cg_prev" ]; then
      cg_prev=
      continue
    fi
    case "$arg" in
      --)
        cg_dd=1
        continue
        ;;
      --*)
        cg_body=${arg#--}
        cg_name=${cg_body%%=*}
        if [ -n "$cg_name" ]; then
          case "file" in
            "$cg_name"*) say_option ;;
          esac
          case "global" in
            "$cg_name"*) say_option ;;
          esac
          case "system" in
            "$cg_name"*) say_option ;;
          esac
          case "blob" in
            "$cg_name"*) say_option ;;
          esac
          case "edit" in
            "$cg_name"*) say_option ;;
          esac
          case "rename-section" in
            "$cg_name"*) say_option ;;
          esac
          case "git-dir" in
            "$cg_name"*) say_option ;;
          esac
          case "work-tree" in
            "$cg_name"*) say_option ;;
          esac
        fi
        case "$cg_name" in
          get|get-all|get-regexp|get-urlmatch|get-color|get-colorbool|list)
            if [ -z "$cg_action" ]; then
              cg_action=read
            fi
            ;;
          unset|unset-all|remove-section)
            cg_action=unset
            ;;
          add|replace-all|append)
            cg_action=write
            ;;
          type|default|comment|value|url)
            case "$arg" in
              --*=*)
                ;;
              *)
                cg_prev=1
                ;;
            esac
            ;;
        esac
        continue
        ;;
      -*)
        cg_rest=${arg#-}
        while [ -n "$cg_rest" ]; do
          cg_letter=${cg_rest%"${cg_rest#?}"}
          cg_rest=${cg_rest#?}
          case "$cg_letter" in
            f|e)
              say_option
              ;;
            l)
              if [ -z "$cg_action" ]; then
                cg_action=read
              fi
              ;;
            t)
              if [ -n "$cg_rest" ]; then
                cg_rest=
              else
                cg_prev=1
              fi
              ;;
          esac
        done
        continue
        ;;
    esac
    if [ -z "$cg_subcmd" ] && [ "$cg_npos" -eq 0 ]; then
      case "$arg" in
        get|list)
          cg_subcmd=$arg
          cg_action=read
          continue
          ;;
        unset|remove-section)
          cg_subcmd=$arg
          cg_action=unset
          continue
          ;;
        set|add)
          cg_subcmd=$arg
          cg_action=write
          continue
          ;;
        edit|rename-section)
          say_option
          ;;
      esac
    fi
    cg_npos=$((cg_npos + 1))
    if [ -z "$cg_key" ]; then
      cg_key=$arg
    fi
  done
  cg_write=
  if [ "$cg_action" = write ]; then
    cg_write=1
  fi
  if [ -z "$cg_action" ] && [ "$cg_npos" -ge 2 ]; then
    cg_write=1
  fi
  if [ "$cg_write" = 1 ] && [ -n "$cg_key" ]; then
    if config_key_allowed "$cg_key"; then
      return 0
    fi
    say_config_key "$cg_key"
  fi
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
# arm=1 marks a repository path that this command itself is opening.
guard_local() {
  cleaned=$(clean_abs "$1") || say_file
  inside_work "$cleaned" || say_file
  phys_inside "$cleaned" || say_file
  if [ "$2" = 1 ]; then
    allow_file=1
  fi
}
accept_local() {
  guard_local "$1" 1
}
check_local() {
  guard_local "$1" 0
}
scan_urls() {
  for arg in "$@"; do
    prefix=$(printf '%s' "$arg" | cut -c 1-7 | tr '[:upper:]' '[:lower:]') || say_file
    if [ "$prefix" = "file://" ]; then
      vet "$arg"
    fi
  done
}
# host:path and localhost:/path are remote URLs, not workspace paths.
colon_remote() {
  case "$1" in
    *://*) return 1 ;;
  esac
  head=${1%%/*}
  case "$head" in
    *:*) return 0 ;;
  esac
  return 1
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
  if colon_remote "$1"; then
    say_deny "$1"
  fi
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
  if colon_remote "$1"; then
    say_deny "$1"
  fi
  case "$1" in
    /*)
      accept_local "$1"
      ;;
    *)
      accept_local "$vet_base/$1"
      ;;
  esac
}
check_local_arg() {
  if colon_remote "$1"; then
    say_deny "$1"
  fi
  case "$1" in
    /*)
      check_local "$1"
      ;;
    *)
      check_local "$vet_base/$1"
      ;;
  esac
}
# An option value that is a repository, a destination, or another path.
vet_opt() {
  case "$1" in
    *://*|git@*)
      vet "$1"
      ;;
    *)
      vet_local "$1"
      ;;
  esac
}
# Bundled clone short options. Digits are flags with no value.
# A u anywhere before an argument value names a remote command.
clone_short() {
  case "$1" in
    -[A-Za-z0-9]*) ;;
    *) return 1 ;;
  esac
  rest=${1#-}
  while [ -n "$rest" ]; do
    letter=${rest%"${rest#?}"}
    case "$letter" in
      [0-9])
        rest=${rest#?}
        ;;
      [A-Za-z])
        rest=${rest#?}
        case "$letter" in
          u)
            say_option
            ;;
          c)
            if [ -n "$rest" ]; then
              url_assign "$rest"
            else
              prev=cfg
            fi
            return 0
            ;;
          b|j|o)
            if [ -z "$rest" ]; then
              prev=skip
            fi
            return 0
            ;;
          q|v|n|l|s)
            ;;
          *)
            return 1
            ;;
        esac
        ;;
      *)
        return 1
        ;;
    esac
  done
  return 0
}
# Bundled fetch short options. j and o take the rest of the word as a value.
# An m before either of those is --multiple.
fetch_multiple_short() {
  case "$sub" in
    fetch) ;;
    *) return 1 ;;
  esac
  case "$1" in
    -[A-Za-z0-9]*) ;;
    *) return 1 ;;
  esac
  rest=${1#-}
  while [ -n "$rest" ]; do
    letter=${rest%"${rest#?}"}
    case "$letter" in
      j|o)
        return 0
        ;;
      m)
        say_option
        ;;
    esac
    rest=${rest#?}
  done
  return 0
}
# A repository config value that names a remote command, or a config
# file pulled in from another path. --no-includes reads every scope
# without opening an included file. The helper read follows includes.
remote_helper_config() {
  found=$("$real" -C "$vet_base" \
    -c core.hooksPath=/dev/null \
    -c core.fsmonitor= \
    -c core.sshCommand=/bin/false \
    -c protocol.allow=never \
    -c safe.directory='*' \
    config --no-includes --get-regexp '^include(if\..*)?\.path$' 2>/dev/null) || found=
  if [ -n "$found" ]; then
    say_config
  fi
  found=$("$real" -C "$vet_base" \
    -c core.hooksPath=/dev/null \
    -c core.fsmonitor= \
    -c core.sshCommand=/bin/false \
    -c protocol.allow=never \
    -c safe.directory='*' \
    config --includes --get-regexp 'remote\..*\.(uploadpack|receivepack|vcs|proxy)$|^url\..*\.(insteadof|pushinsteadof)$' 2>/dev/null) || found=
  if [ -n "$found" ]; then
    say_config
  fi
}
resolve_remote() {
  name=$1
  if colon_remote "$name"; then
    vet "$name"
    found_url=1
    return
  fi
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
quote() {
  printf "'"
  s=$1
  while :; do
    case "$s" in
      *\'*)
        printf "%s'\\''" "${s%%\'*}"
        s=${s#*\'}
        ;;
      *)
        printf "%s" "$s"
        break
        ;;
    esac
  done
  printf "'"
}
# Wrapper -c values follow the caller's global options and precede the git command.
exec_git() {
  pins=
  while [ $# -gt 0 ]; do
    if [ "$1" = "--" ]; then
      shift
      break
    fi
    pins="$pins $(quote "$1")"
    shift
  done
  lead=
  rest=
  seen=
  prev=
  for arg in "$@"; do
    if [ -n "$seen" ]; then
      rest="$rest $(quote "$arg")"
      continue
    fi
    if [ -n "$prev" ]; then
      lead="$lead $(quote "$arg")"
      prev=
      continue
    fi
    case "$arg" in
      -C|-c|--git-dir|--work-tree|--namespace|--super-prefix|--config-env|--exec-path|--config)
        lead="$lead $(quote "$arg")"
        prev=1
        ;;
      --git-dir=*|--work-tree=*|--namespace=*|--super-prefix=*|--config-env=*|--exec-path=*|--config=*|-c*)
        lead="$lead $(quote "$arg")"
        ;;
      --)
        seen=1
        rest="$rest $(quote "$arg")"
        ;;
      -*)
        lead="$lead $(quote "$arg")"
        ;;
      *)
        seen=1
        rest="$rest $(quote "$arg")"
        ;;
    esac
  done
  eval "set -- $lead $pins $rest"
  exec "$real" "$@"
}
run() {
  # "user" allows a top-level local path. Nested git clears the user bit,
  # so it does not keep that permission. Leave the protocol list unset so
  # an inherited value cannot add file for this command or a child.
  if [ "$allow_file" = 1 ]; then
    pfile=user
    unset GIT_ALLOW_PROTOCOL
  else
    pfile=never
    protos=https:ssh
    if [ -n "$GHPORT" ]; then
      protos=$protos:http
    fi
    export GIT_ALLOW_PROTOCOL=$protos
  fi
  if [ "$sub" = diff ] || [ "$sub" = log ] || [ "$sub" = show ]; then
    if [ -x /bin/bash ]; then
      exec /bin/bash --norc --noprofile -c '
real=$1
name=$2
email=$3
port=$4
pfile=$5
sub=$6
shift 6
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
    -C|-c|--git-dir|--work-tree|--namespace|--super-prefix|--config-env|--exec-path|--config)
      args+=("$arg")
      prev=1
      continue
      ;;
    --git-dir=*|--work-tree=*|--namespace=*|--super-prefix=*|--config-env=*|--exec-path=*|--config=*)
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
cargs=(-c user.name="$name" -c user.email="$email" -c commit.gpgsign=false -c core.sshCommand=/bin/false -c core.hooksPath=/dev/null -c protocol.allow=never -c protocol.https.allow=always -c protocol.ssh.allow=always -c protocol.file.allow="$pfile" -c fetch.recurseSubmodules=false -c submodule.recurse=false -c diff.external= -c core.pager=cat -c core.fsmonitor= -c core.fsmonitorHookVersion=)
lead=()
tail=()
prev=
seen=0
for arg in "${args[@]}"; do
  if [ "$seen" = 1 ]; then
    tail+=("$arg")
    continue
  fi
  if [ -n "$prev" ]; then
    lead+=("$arg")
    prev=
    continue
  fi
  case "$arg" in
    -C|-c|--git-dir|--work-tree|--namespace|--super-prefix|--config-env|--exec-path|--config)
      lead+=("$arg")
      prev=1
      ;;
    --git-dir=*|--work-tree=*|--namespace=*|--super-prefix=*|--config-env=*|--exec-path=*|--config=*|-c*)
      lead+=("$arg")
      ;;
    --)
      seen=1
      tail+=("$arg")
      ;;
    -*)
      lead+=("$arg")
      ;;
    *)
      seen=1
      tail+=("$arg")
      ;;
  esac
done
if [ -n "$port" ]; then
  exec "$real" "${lead[@]}" "${cargs[@]}" -c protocol.http.allow=always -c http.proxy= -c "url.http://127.0.0.1:${port}/github/.insteadOf=https://github.com/" -c "url.http://127.0.0.1:${port}/api/.insteadOf=https://api.github.com/" "${tail[@]}"
fi
exec "$real" "${lead[@]}" "${cargs[@]}" "${tail[@]}"
' bash "$real" "$author_name" "$author_email" "$GHPORT" "$pfile" "$sub" "$@"
    fi
  fi
  if [ -n "$GHPORT" ]; then
    exec_git \
      -c user.name="$author_name" \
      -c user.email="$author_email" \
      -c commit.gpgsign=false \
      -c core.sshCommand=/bin/false \
      -c core.hooksPath=/dev/null \
      -c diff.external= \
      -c core.pager=cat \
      -c core.fsmonitor= \
      -c core.fsmonitorHookVersion= \
      -c protocol.allow=never \
      -c protocol.https.allow=always \
      -c protocol.ssh.allow=always \
      -c protocol.http.allow=always \
      -c protocol.file.allow="$pfile" \
      -c fetch.recurseSubmodules=false \
      -c submodule.recurse=false \
      -c http.proxy= \
      -c "url.http://127.0.0.1:${GHPORT}/github/.insteadOf=https://github.com/" \
      -c "url.http://127.0.0.1:${GHPORT}/api/.insteadOf=https://api.github.com/" \
      -- "$@"
  fi
  exec_git \
    -c user.name="$author_name" \
    -c user.email="$author_email" \
    -c commit.gpgsign=false \
    -c core.sshCommand=/bin/false \
    -c core.hooksPath=/dev/null \
    -c diff.external= \
    -c core.pager=cat \
    -c core.fsmonitor= \
    -c core.fsmonitorHookVersion= \
    -c protocol.allow=never \
    -c protocol.https.allow=always \
    -c protocol.ssh.allow=always \
    -c protocol.file.allow="$pfile" \
    -c fetch.recurseSubmodules=false \
    -c submodule.recurse=false \
    -- "$@"
}
scan_global "$@"
# --git-dir and --work-tree select a repository the cwd checks did not read.
# Read-only commands may still name one.
if [ "$saw_repo_opt" = 1 ]; then
  case "$sub" in
    ""|status|diff|log|show|rev-parse|blame|ls-files|grep|version|help|describe|name-rev|cat-file|shortlog|var)
      ;;
    *)
      say_option
      ;;
  esac
fi
scan_urls "$@"
# Effective config, including included files and worktree config.
# git config stays available so a refused key can be removed.
# Command-line pins are not repository keys and are skipped.
# gitdir_args is expanded in a subshell so this command's arguments stay intact.
# A missing git binary is not a repository key. The later checks still run.
if [ "$sub" != config ] && [ -x "$real" ]; then
  cfg_tab=$(printf '\t')
  lines=$(
    eval "set -- $gitdir_args"
    "$real" -C "$vet_base" "$@" \
      -c core.hooksPath=/dev/null \
      -c core.fsmonitor= \
      -c core.sshCommand=/bin/false \
      -c protocol.allow=never \
      -c safe.directory='*' \
      config --includes --name-only --list --show-origin 2>/dev/null
  ) || say_config
  cfg_rest=$lines
  while [ -n "$cfg_rest" ]; do
    case "$cfg_rest" in
      *"$nl"*)
        cfg_line=${cfg_rest%%"$nl"*}
        cfg_rest=${cfg_rest#*"$nl"}
        ;;
      *)
        cfg_line=$cfg_rest
        cfg_rest=
        ;;
    esac
    case "$cfg_line" in
      ""|"command line:"*)
        continue
        ;;
    esac
    cfg_key=$cfg_line
    case "$cfg_line" in
      *"$cfg_tab"*)
        cfg_key=${cfg_line#*"$cfg_tab"}
        ;;
    esac
    if config_key_allowed "$cfg_key"; then
      ck_fold=$(printf '%s' "$cfg_key" | tr '[:upper:]' '[:lower:]') || say_config
      case "$ck_fold" in
        core.worktree)
          check_core_worktree
          ;;
      esac
      continue
    fi
    say_config_key "$cfg_key"
  done
fi
if [ "$sub" = config ]; then
  config_guard "$@"
fi
# An alias hides the command word. Git does not let an alias replace a builtin.
# Any stored alias key is refused by the check above, including one that is not invoked.
if [ -n "$sub" ]; then
  found=$(
    eval "set -- $gitdir_args"
    "$real" -C "$vet_base" "$@" \
      -c core.hooksPath=/dev/null \
      -c core.fsmonitor= \
      -c core.sshCommand=/bin/false \
      -c protocol.allow=never \
      -c safe.directory='*' \
      config --includes --get "alias.$sub" 2>/dev/null
  ) || found=
  if [ -n "$found" ]; then
    say_config
  fi
fi
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
  for arg in "$@"; do
    refuse_command_opt "$arg"
  done
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
    remote_helper_config
    prev=
    seen_sub=
    for arg in "$@"; do
      if [ -n "$prev" ]; then
        case "$prev" in
          cfg)
            url_assign "$arg"
            ;;
          path)
            vet_opt "$arg"
            ;;
        esac
        prev=
        continue
      fi
      refuse_command_opt "$arg"
      refuse_submodule_opt "$arg"
      fetch_multiple_short "$arg"
      if [ "$sub" = clone ] && clone_short "$arg"; then
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
        --reference|--reference-if-able|--separate-git-dir|--template|--bundle-uri)
          prev=path
          continue
          ;;
        --reference=*|--reference-if-able=*|--separate-git-dir=*|--template=*|--bundle-uri=*)
          vet_opt "${arg#*=}"
          continue
          ;;
        -u|-u*)
          if [ "$sub" = clone ]; then
            say_option
          fi
          continue
          ;;
        -C|--git-dir|--work-tree|--namespace|--super-prefix|--exec-path|--depth|--branch|-b|--origin|-o|--server-option|--jobs|-j|--filter|--shallow-since|--shallow-exclude|--revision)
          prev=skip
          continue
          ;;
        --git-dir=*|--work-tree=*|--namespace=*|--super-prefix=*|--exec-path=*|--depth=*|--branch=*|--origin=*|--server-option=*|--jobs=*|--filter=*|--shallow-since=*|--shallow-exclude=*|--revision=*)
          continue
          ;;
        -j*|-b*|-o*)
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
      if [ "$sub" = remote ] && [ -z "$remote_sub" ]; then
        case "$arg" in
          add|prune|update|show|set-url|get-url|rename|remove|rm|set-head|set-branches)
            remote_sub=$arg
            continue
            ;;
        esac
      fi
      if colon_remote "$arg"; then
        vet "$arg"
        found_url=1
        continue
      fi
      case "$arg" in
        *://*|git@*)
          vet "$arg"
          found_url=1
          ;;
        *)
          if [ "$sub" = clone ]; then
            vet_local "$arg"
            found_url=1
          elif [ "$sub" = submodule ]; then
            case "$arg" in
              /*|./*|../*|..|*/..|*/../*|*/*|.)
                check_local_arg "$arg"
                ;;
              *)
                if [ -z "$pos" ]; then
                  pos=$arg
                fi
                ;;
            esac
          else
            case "$arg" in
              /*|./*|../*|..|*/..|*/../*|*/*|.)
                vet "$arg"
                found_url=1
                ;;
              *)
                # remote prune, update and show contact every named remote, so each name is read.
                case "$sub:$remote_sub" in
                  remote:prune|remote:update|remote:show)
                    remote_names="$remote_names$arg$nl"
                    ;;
                esac
                if [ -z "$pos" ]; then
                  pos=$arg
                fi
                ;;
            esac
          fi
          ;;
      esac
    done
    remote_rest=$remote_names
    while [ -n "$remote_rest" ]; do
      remote_one=${remote_rest%%"$nl"*}
      remote_rest=${remote_rest#*"$nl"}
      resolve_remote "$remote_one"
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
    # remote add fetches with -f or --fetch, so it keeps the bridge then.
    case "$remote_sub" in
      add)
        remote_fetches=
        for arg in "$@"; do
          case "$arg" in
            --fetch|--fetch=*|-f|-[A-Za-z]*f*)
              remote_fetches=1
              ;;
          esac
        done
        if [ -z "$remote_fetches" ]; then
          need_bridge=0
        fi
        ;;
      set-url|remove|rm|rename|get-url|set-head|set-branches)
        need_bridge=0
        ;;
    esac
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
