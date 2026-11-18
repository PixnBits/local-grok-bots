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
# Git expands a leading "~" against HOME. The workspace root is the only home.
export HOME=/work
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
contact_all=0
sm_action=
sm_url_set=
sm_url_armed=
pos=
remote_sub=
remote_names=
remote_npos=0
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
# The path could not be walked to a directory inside the workspace.
# This is not the outside-workspace refusal.
say_file_path() {
  echo "git ${sub} denied: local path cannot be resolved inside the workspace" >&2
  printf '%s\n' "deny git ${sub}" >> "$log"
  exit 1
}
# A leading "~" is not a workspace path. Git expands it in a transport URL.
say_tilde() {
  echo "git ${sub} denied: a ~ path is not supported" >&2
  printf '%s\n' "deny git ${sub}" >> "$log"
  exit 1
}
say_config() {
  echo "git ${sub} denied: configuration is not allowed" >&2
  printf '%s\n' "deny git ${sub}" >> "$log"
  exit 1
}
say_config_key() {
  # Keep the safe characters. Every other byte becomes "?", including controls.
  # The length of the printed key stays the same, up to 100 bytes.
  sk_key=$(printf '%s' "$1" | LC_ALL=C tr -c 'A-Za-z0-9._*-' '?' | LC_ALL=C cut -c 1-100)
  echo "git ${sub} denied: configuration is not allowed: ${sk_key}" >&2
  printf '%s\n' "deny git ${sub}" >> "$log"
  exit 1
}
say_option() {
  echo "git ${sub} denied: option is not allowed" >&2
  printf '%s\n' "deny git ${sub}" >> "$log"
  exit 1
}
say_remote_name() {
  echo "git ${sub} denied: remote name is not allowed" >&2
  printf '%s\n' "deny git ${sub}" >> "$log"
  exit 1
}
say_sub_rel() {
  echo "git ${sub} denied: relative submodule URL is not supported; use an absolute /work path or a file:// URL inside the workspace" >&2
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
# A remote name is letters, digits, ".", "_", or "-".
# "." and ".." are not names. A name does not start with "-" or contain "/".
remote_name_ok() {
  case "$1" in
    ""|.|..|-*|*[!A-Za-z0-9._-]*) return 1 ;;
  esac
  return 0
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
    # remote and pushremote are "." or the name of a configured remote.
    branch.*.remote|branch.*.merge|branch.*.rebase|branch.*.description|branch.*.pushremote)
      ;;
    # Remote definition. The url is checked again when a command uses it.
    # The name is the text between the first "remote." and the last ".".
    remote.*.url|remote.*.fetch)
      rn=${ck_key#remote.}
      rn=${rn%.*}
      remote_name_ok "$rn" || return 1
      ;;
    # Written by clone --no-tags and clone --mirror.
    remote.*.tagopt)
      rn=${ck_key#remote.}
      rn=${rn%.*}
      remote_name_ok "$rn" || return 1
      ;;
    # Written by clone --mirror. It marks a mirror remote and does not name a command.
    remote.*.mirror)
      rn=${ck_key#remote.}
      rn=${rn%.*}
      remote_name_ok "$rn" || return 1
      ;;
    # Written by init --object-format=sha256.
    extensions.objectformat)
      ;;
    # Author identity. Refusing these would lock the repository after git config user.name.
    user.name|user.email)
      ;;
    # Written by submodule add. The url is checked like a remote url. active is unchanged.
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
    # help.autocorrect is allowed only for the off values.
    help.autocorrect)
      ;;
    # commit.gpgsign is allowed only when signing is off.
    commit.gpgsign)
      ;;
    # pack.threads is an integer from 0 to 256. It does not name a command.
    pack.threads)
      ;;
    *)
      return 1
      ;;
  esac
  return 0
}
# "." or a configured remote name. A path or URL is refused.
branch_remote_ok() {
  case "$1" in
    .) return 0 ;;
    ""|-*|*[!A-Za-z0-9._-]*) return 1 ;;
  esac
  # $1 is cleared by set -- inside the command substitution, so keep the name.
  bro_name=$1
  bro_out=$(
    eval "set -- $gitdir_args"
    "$real" -C "$vet_base" "$@" \
      -c core.hooksPath=/dev/null \
      -c core.fsmonitor= \
      -c core.sshCommand=/bin/false \
      -c protocol.allow=never \
      -c safe.directory='*' \
      remote get-url -- "$bro_name" 2>/dev/null
  ) || return 1
  [ -n "$bro_out" ]
}
# Shared value rule for keys that are not free-form.
# A key with no value rule is allowed. A newline in the value is refused.
config_value_allowed() {
  cva_key=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]') || return 1
  cva_val=$2
  cva_tab=$(printf '\t')
  case "$cva_val" in
    *"$nl"*|*"$cva_tab"*) return 1 ;;
  esac
  case "$cva_key" in
    branch.*.remote|branch.*.pushremote)
      branch_remote_ok "$cva_val"
      return $?
      ;;
    remote.*.tagopt)
      case "$cva_val" in
        --no-tags|--tags) return 0 ;;
      esac
      return 1
      ;;
    submodule.*.url)
      case "$cva_val" in
        ./*|../*)
          case "$cva_val" in
            *:*) return 1 ;;
          esac
          submodule_rel_ok "$cva_val" || return 1
          return 0
          ;;
      esac
      if ! (
        log=/dev/null
        vet "$cva_val" >/dev/null 2>&1
      ); then
        return 1
      fi
      case "$cva_val" in
        *://*|git@*|/*) return 0 ;;
      esac
      return 1
      ;;
    help.autocorrect)
      case "$cva_val" in
        0|never|false|no|off) return 0 ;;
      esac
      return 1
      ;;
    commit.gpgsign)
      case "$cva_val" in
        false|no|off|0) return 0 ;;
      esac
      return 1
      ;;
    pack.threads)
      # Digits only, at most three, so the comparison cannot overflow.
      case "$cva_val" in
        ""|*[!0-9]*|[0-9][0-9][0-9][0-9]*) return 1 ;;
      esac
      if [ "$cva_val" -gt 256 ]; then
        return 1
      fi
      return 0
      ;;
  esac
  return 0
}
# A relative submodule url is resolved lexically from /work and must stay there.
# The resolved path must also be physically inside /work.
submodule_rel_ok() {
  sru_rest=$1
  sru_path=/work
  while [ -n "$sru_rest" ]; do
    sru_seg=${sru_rest%%/*}
    if [ "$sru_rest" = "$sru_seg" ]; then
      sru_rest=
    else
      sru_rest=${sru_rest#*/}
    fi
    case "$sru_seg" in
      ""|.)
        continue
        ;;
      ..)
        case "$sru_path" in
          /work) return 1 ;;
          /work/*) sru_path=${sru_path%/*} ;;
          *) return 1 ;;
        esac
        ;;
      *)
        sru_path=$sru_path/$sru_seg
        ;;
    esac
  done
  inside_work "$sru_path" || return 1
  phys_inside "$sru_path"
}
# Read every stored value of a restricted key.
# A newline in a stored value is translated to SOH. Refuse that before the
# value rule. A path value can still match the path rule after translation.
config_check_values() {
  cck_probe=$(printf '\001')
  if config_value_allowed "$1" "$cck_probe"; then
    return 0
  fi
  cck_key=$1
  cck_raw=$(
    eval "set -- $gitdir_args"
    "$real" -C "$vet_base" "$@" \
      -c core.hooksPath=/dev/null \
      -c core.fsmonitor= \
      -c core.sshCommand=/bin/false \
      -c protocol.allow=never \
      -c safe.directory='*' \
      config --includes --null --get-all -- "$cck_key" 2>/dev/null | tr '\000\n' '\n\001'
  ) || say_config_key "$cck_key"
  cck_soh=$(printf '\001')
  case "$cck_raw" in
    *"$cck_soh"*) say_config_key "$cck_key" ;;
  esac
  if [ -z "$cck_raw" ]; then
    say_config_key "$cck_key"
  fi
  cck_rest=$cck_raw
  while [ -n "$cck_rest" ]; do
    case "$cck_rest" in
      *"$nl"*)
        cck_one=${cck_rest%%"$nl"*}
        cck_rest=${cck_rest#*"$nl"}
        ;;
      *)
        cck_one=$cck_rest
        cck_rest=
        ;;
    esac
    config_value_allowed "$cck_key" "$cck_one" || say_config_key "$cck_key"
  done
}
# core.worktree is allowed only when the value is relative and, after a physical
# chdir from the git directory, stays inside /work.
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
    wt_resolved=$(cd -P -- "$wt_gitdir/$wt_val" && pwd -P) || say_config_key "core.worktree"
    inside_work "$wt_resolved" || say_config_key "core.worktree"
  done
}
# A plain path is not a URL. remote.*.url plain paths are checked on write.
remote_url_plain() {
  case "$1" in
    *://*|git@*) return 1 ;;
  esac
  if colon_remote "$1"; then
    return 1
  fi
  case "$1" in
    ~*|/*|./*|../*|.|..|*/*) return 0 ;;
  esac
  return 1
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
  cg_val=
  cg_val_set=
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
      elif [ -z "$cg_val_set" ]; then
        cg_val=$arg
        cg_val_set=1
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
        # A dash-leading word after the key is a value, as with tag.sort.
        if [ -n "$cg_key" ]; then
          cg_npos=$((cg_npos + 1))
          if [ -z "$cg_val_set" ]; then
            cg_val=$arg
            cg_val_set=1
          fi
          continue
        fi
        cg_body=${arg#--}
        cg_name=${cg_body%%=*}
        # A long option is refused unless its name is an exact known form.
        # Abbreviations of value-taking options are refused here.
        case "$cg_name" in
          null|comment|type|default|value|url|add|replace-all|append|unset|unset-all|remove-section|get|get-all|get-regexp|get-urlmatch|get-color|get-colorbool|list|name-only|show-origin|show-scope|includes|no-includes|local|worktree)
            ;;
          *)
            say_option
            ;;
        esac
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
        if [ -n "$cg_key" ]; then
          cg_npos=$((cg_npos + 1))
          if [ -z "$cg_val_set" ]; then
            cg_val=$arg
            cg_val_set=1
          fi
          continue
        fi
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
    elif [ -z "$cg_val_set" ]; then
      cg_val=$arg
      cg_val_set=1
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
      if [ "$cg_val_set" = 1 ]; then
        config_value_allowed "$cg_key" "$cg_val" || say_config_key "$cg_key"
        cg_fold=$(printf '%s' "$cg_key" | tr '[:upper:]' '[:lower:]') || say_config_key "$cg_key"
        case "$cg_fold" in
          remote.*.url)
            # A plain path, a trailing-slash relative path, a leading "~",
            # and a slashless name that exists beside the command are local paths.
            # A slashless name that does not exist is left unchanged.
            cg_as_path=
            if remote_url_plain "$cg_val"; then
              cg_as_path=1
            elif [ -e "$vet_base/$cg_val" ] || [ -L "$vet_base/$cg_val" ]; then
              case "$cg_val" in
                */*) ;;
                *)
                  if ! colon_remote "$cg_val"; then
                    cg_as_path=1
                  fi
                  ;;
              esac
            fi
            if [ "$cg_as_path" = 1 ]; then
              if ! (
                log=/dev/null
                vet_local "$cg_val" >/dev/null 2>&1
              ); then
                say_config_key "$cg_key"
              fi
            fi
            ;;
        esac
      fi
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
# An option value is not the repository. Paths and URLs are checked and do not arm file.
check_skipped() {
  cs_file=$allow_file
  cs_bridge=$need_bridge
  cs_found=$found_url
  case "$1" in
    "")
      ;;
    *)
      cs_prefix=$(printf '%s' "$1" | cut -c 1-7 | tr '[:upper:]' '[:lower:]') || say_file
      if [ "$cs_prefix" = "file://" ]; then
        cs_pth=$(file_url_path "$1") || say_file
        check_local "$cs_pth"
      else
        case "$1" in
          *://*|git@*)
            vet "$1"
            ;;
          /*)
            check_local "$1"
            ;;
          ./*|../*|..|*/..|*/../*)
            check_local_arg "$1"
            ;;
        esac
      fi
      ;;
  esac
  allow_file=$cs_file
  need_bridge=$cs_bridge
  found_url=$cs_found
}
scan_urls() {
  for arg in "$@"; do
    prefix=$(printf '%s' "$arg" | cut -c 1-7 | tr '[:upper:]' '[:lower:]') || say_file
    if [ "$prefix" = "file://" ]; then
      su_pth=$(file_url_path "$arg") || say_file
      check_local "$su_pth"
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
    # Kept beside the positional and --repo checks.
    ~*) say_tilde ;;
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
  # A slashless name that exists beside the command is a local path.
  if [ -e "$vet_base/$1" ] || [ -L "$vet_base/$1" ]; then
    vet_local "$1"
    return 0
  fi
  return 0
}
vet_local() {
  case "$1" in
    # Kept beside the positional and --repo checks.
    ~*) say_tilde ;;
  esac
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
  case "$1" in
    # Kept beside the positional and --repo checks.
    ~*) say_tilde ;;
  esac
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
# Checked only. It does not arm the file protocol.
vet_opt() {
  vo_file=$allow_file
  vo_bridge=$need_bridge
  vo_found=$found_url
  case "$1" in
    *://*|git@*)
      vet "$1"
      ;;
    *)
      vet_local "$1"
      ;;
  esac
  allow_file=$vo_file
  need_bridge=$vo_bridge
  found_url=$vo_found
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
          b|j)
            if [ -z "$rest" ]; then
              prev=skip
            fi
            return 0
            ;;
          o)
            if [ -n "$rest" ]; then
              remote_name_ok "$rest" || say_remote_name
            else
              prev=origin
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
    "")
      return
      ;;
    *://*|git@*)
      vet "$name"
      found_url=1
      return
      ;;
    # A path-shaped word can still name a configured remote.
    # Vet every stored URL, then vet the word as a path.
    # A leading "-" is not vetted as a path. Its stored URLs are still vetted.
    -*|/*|./*|../*|..|*/..|*/../*|*/*|.)
      rr_urls=$(
        eval "set -- $gitdir_args"
        "$real" -C "$vet_base" "$@" \
          -c core.hooksPath=/dev/null \
          -c core.fsmonitor= \
          -c core.sshCommand=/bin/false \
          -c protocol.allow=never \
          -c safe.directory='*' \
          config --includes --get-all -- "remote.$name.url" 2>/dev/null
      ) || rr_urls=
      rr_rest=$rr_urls
      while [ -n "$rr_rest" ]; do
        case "$rr_rest" in
          *"$nl"*)
            rr_one=${rr_rest%%"$nl"*}
            rr_rest=${rr_rest#*"$nl"}
            ;;
          *)
            rr_one=$rr_rest
            rr_rest=
            ;;
        esac
        if [ -z "$rr_one" ]; then
          continue
        fi
        vet "$rr_one"
      done
      case "$name" in
        -*) return ;;
      esac
      vet "$name"
      found_url=1
      return
      ;;
  esac
  # A configured remote is its stored URL, not a directory of the same name.
  u=$(
    eval "set -- $gitdir_args"
    "$real" -C "$vet_base" "$@" \
      -c core.hooksPath=/dev/null \
      -c core.fsmonitor= \
      -c core.sshCommand=/bin/false \
      -c protocol.allow=never \
      -c safe.directory='*' \
      remote get-url -- "$name" 2>/dev/null
  ) || u=
  if [ -n "$u" ]; then
    vet "$u"
    return
  fi
  if [ -e "$vet_base/$name" ] || [ -L "$vet_base/$name" ]; then
    vet_local "$name"
    found_url=1
  fi
}
# Same check as resolve_remote, without arming and without keeping a bridge flag.
resolve_remote_check() {
  rrc_file=$allow_file
  rrc_bridge=$need_bridge
  rrc_found=$found_url
  resolve_remote "$1"
  allow_file=$rrc_file
  need_bridge=$rrc_bridge
  found_url=$rrc_found
}
list_remotes() {
  eval "set -- $gitdir_args"
  "$real" -C "$vet_base" "$@" \
    -c core.hooksPath=/dev/null \
    -c core.fsmonitor= \
    -c core.sshCommand=/bin/false \
    -c protocol.allow=never \
    -c safe.directory='*' \
    remote 2>/dev/null
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
    # submodule add clones in a child. That child does not keep the user bit.
    # Name file only when this add's URL positional was the word that armed it.
    if [ "$sub" = submodule ] && [ "$sm_action" = add ] && [ "$sm_url_armed" = 1 ]; then
      export GIT_ALLOW_PROTOCOL=file
    fi
  else
    pfile=never
    protos=https:ssh
    if [ -n "$GHPORT" ]; then
      protos=$protos:http
    fi
    export GIT_ALLOW_PROTOCOL=$protos
  fi
  # update, init, sync, foreach, and status never use the file protocol.
  if [ "$sub" = submodule ] && [ "$sm_action" != add ]; then
    pfile=never
    protos=https:ssh
    if [ -n "$GHPORT" ]; then
      protos=$protos:http
    fi
    unset GIT_ALLOW_PROTOCOL
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
# A long option takes a value when its name is a unique prefix of one of these.
skip_value_name() {
  if [ -z "$1" ]; then
    return 1
  fi
  sv_hits=0
  for sv_cand in depth branch origin server-option jobs filter shallow-since shallow-exclude revision negotiation-tip deepen refmap; do
    case "$sv_cand" in
      "$1"*) sv_hits=$((sv_hits + 1)) ;;
    esac
  done
  [ "$sv_hits" -eq 1 ]
}
# Print one effective config value. Empty when the key is unset.
qget() {
  qget_key=$1
  qget_out=$(
    eval "set -- $gitdir_args"
    "$real" -C "$vet_base" "$@" \
      -c core.hooksPath=/dev/null \
      -c core.fsmonitor= \
      -c core.sshCommand=/bin/false \
      -c protocol.allow=never \
      -c safe.directory='*' \
      config --includes --get -- "$qget_key" 2>/dev/null
  ) || qget_out=
  printf '%s' "$qget_out"
}
# No repository word: check the branch remote the same way as a named remote.
# --short prints heads/main when a tag shares the branch name, so the full ref is read.
# A detached HEAD has no branch ref. Fetch then checks origin and nothing else for the branch.
resolve_branch_remote() {
  br_full=$(
    eval "set -- $gitdir_args"
    "$real" -C "$vet_base" "$@" \
      -c core.hooksPath=/dev/null \
      -c core.fsmonitor= \
      -c core.sshCommand=/bin/false \
      -c protocol.allow=never \
      -c safe.directory='*' \
      symbolic-ref -q HEAD 2>/dev/null
  ) || br_full=
  case "$br_full" in
    *"$nl"*) br_full= ;;
  esac
  br_name=
  case "$br_full" in
    refs/heads/*)
      br_name=${br_full#refs/heads/}
      ;;
  esac
  br_hit=
  br_fetch=
  if [ -n "$br_name" ]; then
    br_key=$(printf 'branch.%s.remote' "$br_name")
    br_val=$(qget "$br_key")
    if [ -n "$br_val" ]; then
      resolve_remote "$br_val"
      br_hit=1
      br_fetch=1
    fi
    br_key=$(printf 'branch.%s.pushremote' "$br_name")
    br_val=$(qget "$br_key")
    if [ -n "$br_val" ]; then
      if [ "$sub" = push ]; then
        resolve_remote "$br_val"
      else
        resolve_remote_check "$br_val"
      fi
      br_hit=1
    fi
  fi
  if [ "$sub" = push ]; then
    if [ -z "$br_hit" ]; then
      resolve_remote origin
    fi
  else
    if [ -z "$br_fetch" ]; then
      resolve_remote origin
    fi
  fi
}
# Return 0 when push already names a remote. Otherwise the branch remote is checked.
push_names_remote() {
  pn_prev=
  pn_seen=
  pn_dd=
  pn_n=0
  for arg in "$@"; do
    if [ -n "$pn_prev" ]; then
      pn_prev=
      continue
    fi
    case "$arg" in
      -C|-c|--git-dir|--work-tree|--namespace|--super-prefix|--config-env|--exec-path|--config|--attr-source)
        pn_prev=1
        continue
        ;;
      --git-dir=*|--work-tree=*|--namespace=*|--super-prefix=*|--config-env=*|--exec-path=*|--config=*|--attr-source=*|-c*)
        continue
        ;;
      --repo|--receive-pack|--exec|--push-option|-o)
        pn_prev=1
        continue
        ;;
      --repo=*|--recurse-submodules|--recurse-submodules=*|--receive-pack=*|--exec=*|--push-option=*|-o*)
        continue
        ;;
    esac
    if [ -z "$pn_seen" ]; then
      case "$arg" in
        --)
          continue
          ;;
        -*)
          continue
          ;;
        *)
          pn_seen=1
          continue
          ;;
      esac
    fi
    if [ -z "$pn_dd" ]; then
      case "$arg" in
        --)
          pn_dd=1
          continue
          ;;
        -*)
          continue
          ;;
      esac
    fi
    pn_n=$((pn_n + 1))
  done
  [ "$pn_n" -ge 1 ]
}
# Locate the git directory from the filesystem. Git is not asked, so core.worktree is not used.
find_git_dir() {
  fg_dir=$vet_base
  fg_i=0
  while [ "$fg_i" -lt 40 ]; do
    inside_work "$fg_dir" || return 1
    if [ -e "$fg_dir/.git" ] || [ -L "$fg_dir/.git" ]; then
      fg_phys=
      if [ -d "$fg_dir/.git" ]; then
        fg_phys=$(cd -P -- "$fg_dir/.git" && pwd -P) || return 1
      elif [ -f "$fg_dir/.git" ]; then
        IFS= read -r fg_line < "$fg_dir/.git" || return 1
        case "$fg_line" in
          gitdir:*) ;;
          *) return 1 ;;
        esac
        fg_rest=${fg_line#gitdir:}
        fg_tab=$(printf '\t')
        while :; do
          case "$fg_rest" in
            " "*) fg_rest=${fg_rest# } ;;
            "$fg_tab"*) fg_rest=${fg_rest#"$fg_tab"} ;;
            *) break ;;
          esac
        done
        if [ -z "$fg_rest" ]; then
          return 1
        fi
        case "$fg_rest" in
          /*) fg_target=$fg_rest ;;
          *) fg_target=$fg_dir/$fg_rest ;;
        esac
        fg_phys=$(cd -P -- "$fg_target" && pwd -P) || return 1
      else
        return 1
      fi
      inside_work "$fg_phys" || return 1
      phys_inside "$fg_phys" || return 1
      printf '%s' "$fg_phys"
      return 0
    fi
    case "$fg_dir" in
      /work|/) return 1 ;;
    esac
    fg_parent=$(dirname "$fg_dir")
    if [ "$fg_parent" = "$fg_dir" ]; then
      return 1
    fi
    fg_dir=$fg_parent
    fg_i=$((fg_i + 1))
  done
  return 1
}
# Removal forms run with --git-dir and --work-tree set to the git directory,
# so git does not chdir through core.worktree.
config_run_unset() {
  cru_gd=$(find_git_dir) || {
    run "$@"
    return
  }
  cru_prev=
  cru_seen=
  cru_args=
  for arg in "$@"; do
    if [ -n "$cru_seen" ]; then
      cru_args="$cru_args $(quote "$arg")"
      continue
    fi
    if [ -n "$cru_prev" ]; then
      cru_prev=
      continue
    fi
    case "$arg" in
      -C|-c|--git-dir|--work-tree|--namespace|--super-prefix|--config-env|--exec-path|--config|--attr-source)
        cru_prev=1
        ;;
      --git-dir=*|--work-tree=*|--namespace=*|--super-prefix=*|--config-env=*|--exec-path=*|--config=*|--attr-source=*|-c*)
        ;;
      *)
        cru_seen=1
        cru_args="$cru_args $(quote "$arg")"
        ;;
    esac
  done
  cd -- "$cru_gd" || say_config
  eval "set -- $cru_args"
  exec_git \
    --git-dir="$cru_gd" \
    --work-tree="$cru_gd" \
    -c core.hooksPath=/dev/null \
    -c core.fsmonitor= \
    -c core.sshCommand=/bin/false \
    -c protocol.allow=never \
    -c safe.directory='*' \
    -- "$@"
}
# template, or separate-git-dir when that prefix is not also shared.
init_path_name() {
  if [ -z "$1" ]; then
    return 1
  fi
  case "template" in
    "$1"*) return 0 ;;
  esac
  case "separate-git-dir" in
    "$1"*)
      case "shared" in
        "$1"*) return 1 ;;
      esac
      return 0
      ;;
  esac
  return 1
}
init_skip_name() {
  if [ -z "$1" ]; then
    return 1
  fi
  is_hits=0
  for is_cand in initial-branch object-format ref-format; do
    case "$is_cand" in
      "$1"*) is_hits=$((is_hits + 1)) ;;
    esac
  done
  [ "$is_hits" -eq 1 ]
}
# An init path must stay inside /work.
# Each existing segment is walked physically. ".." is the physical parent.
# A missing segment starts an unborn tail. ".." in that tail removes the last
# tail segment. A missing segment is not a symlink. When the tail is empty,
# the walk continues from the physical directory, and ".." is the physical
# parent. The physical directory and any remaining tail must stay inside /work.
# "local path is outside the workspace" is only for a path that resolves outside.
# A component that cannot be walked uses say_file_path.
init_vet() {
  case "$1" in
    "") say_file_path ;;
    /*) iv_abs=$1 ;;
    *) iv_abs=$vet_base/$1 ;;
  esac
  case "$iv_abs" in
    /*) ;;
    *) say_file_path ;;
  esac
  iv_cur=/
  iv_rest=
  iv_tail=
  iv_walk=${iv_abs#/}
  while [ -n "$iv_walk" ]; do
    iv_seg=${iv_walk%%/*}
    if [ "$iv_walk" = "$iv_seg" ]; then
      iv_walk=
    else
      iv_walk=${iv_walk#*/}
    fi
    iv_last=
    if [ -z "$iv_walk" ]; then
      iv_last=1
    fi
    if [ -n "$iv_tail" ]; then
      case "$iv_seg" in
        ""|.) continue ;;
        ..)
          case "$iv_rest" in
            */*)
              iv_rest=${iv_rest%/*}
              ;;
            *)
              iv_rest=
              iv_tail=
              ;;
          esac
          continue
          ;;
      esac
      if [ -z "$iv_rest" ]; then
        iv_rest=$iv_seg
      else
        iv_rest=$iv_rest/$iv_seg
      fi
      continue
    fi
    case "$iv_seg" in
      ""|.) continue ;;
      ..)
        iv_cur=$(cd -P -- "$iv_cur/.." 2>/dev/null && pwd -P) || say_file_path
        continue
        ;;
    esac
    if [ "$iv_cur" = / ]; then
      iv_next=/$iv_seg
    else
      iv_next=$iv_cur/$iv_seg
    fi
    if [ -e "$iv_next" ] || [ -L "$iv_next" ]; then
      if [ -d "$iv_next" ]; then
        iv_cur=$(cd -P -- "$iv_next" 2>/dev/null && pwd -P) || say_file_path
        continue
      fi
      if [ -n "$iv_last" ] && [ ! -L "$iv_next" ]; then
        iv_cur=$(cd -P -- "$iv_cur" 2>/dev/null && pwd -P) || say_file_path
        inside_work "$iv_cur" || say_file
        return 0
      fi
      say_file_path
    fi
    iv_tail=1
    iv_rest=$iv_seg
  done
  inside_work "$iv_cur" || say_file
  if [ -n "$iv_rest" ]; then
    if [ "$iv_cur" = / ]; then
      inside_work "/$iv_rest" || say_file
    else
      inside_work "$iv_cur/$iv_rest" || say_file
    fi
  fi
}
guard_init() {
  gi_prev=
  gi_seen=
  gi_skip=
  gi_path=
  gi_dd=
  for arg in "$@"; do
    if [ -z "$gi_seen" ]; then
      if [ -n "$gi_prev" ]; then
        gi_prev=
        continue
      fi
      case "$arg" in
        -C|-c|--git-dir|--work-tree|--namespace|--super-prefix|--config-env|--exec-path|--config|--attr-source)
          gi_prev=1
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
        init)
          gi_seen=1
          continue
          ;;
        *)
          gi_seen=1
          ;;
      esac
    fi
    if [ -n "$gi_path" ]; then
      gi_path=
      init_vet "$arg"
      continue
    fi
    if [ -n "$gi_skip" ]; then
      gi_skip=
      continue
    fi
    if [ -n "$gi_dd" ]; then
      init_vet "$arg"
      continue
    fi
    case "$arg" in
      --)
        gi_dd=1
        continue
        ;;
      --*=*)
        gi_body=${arg#--}
        gi_name=${gi_body%%=*}
        if init_path_name "$gi_name"; then
          init_vet "${arg#*=}"
        fi
        continue
        ;;
      --*)
        gi_name=${arg#--}
        if init_path_name "$gi_name"; then
          gi_path=1
        elif init_skip_name "$gi_name"; then
          gi_skip=1
        fi
        continue
        ;;
      -b)
        gi_skip=1
        continue
        ;;
      -*)
        continue
        ;;
      *)
        init_vet "$arg"
        ;;
    esac
  done
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
# config values are checked after config_guard so a refused key is named.
if [ "$sub" != config ]; then
  scan_urls "$@"
fi
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
      config_check_values "$cfg_key"
      continue
    fi
    say_config_key "$cfg_key"
  done
fi
if [ "$sub" = config ]; then
  config_guard "$@"
  # An allowed config value can still be a file URL. Checked, not armed.
  scan_urls "$@"
  if [ "$cg_action" = unset ]; then
    config_run_unset "$@"
  fi
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
# remote add long options, matched the way git matches a unique prefix.
# track and master take a value (the next word, or the text after "=").
# mirror takes only an optional "=value". The next word is not that value.
# fetch, tags, and the no- forms take no value. Any other spelling is refused.
remote_add_long() {
  ra_body=${1#--}
  ra_name=${ra_body%%=*}
  ra_eq=0
  case "$1" in
    --*=*) ra_eq=1 ;;
  esac
  case "$ra_name" in
    ""|*[!A-Za-z0-9-]*) say_option ;;
  esac
  ra_hits=0
  ra_kind=
  ra_hit=
  for ra_cand in fetch:flag tags:flag track:value master:value mirror:mirror no-fetch:flag no-tags:flag no-track:flag no-master:flag no-mirror:flag; do
    ra_opt=${ra_cand%%:*}
    ra_k=${ra_cand#*:}
    case "$ra_opt" in
      "$ra_name"*)
        ra_hits=$((ra_hits + 1))
        ra_kind=$ra_k
        ra_hit=$ra_opt
        ;;
    esac
  done
  if [ "$ra_hits" -ne 1 ]; then
    say_option
  fi
  case "$ra_kind" in
    value)
      if [ "$ra_eq" != 1 ]; then
        prev=skip
      fi
      ;;
    flag)
      if [ "$ra_eq" = 1 ]; then
        say_option
      fi
      # A unique prefix of fetch is a fetch for the bridge decision.
      if [ "$ra_hit" = fetch ]; then
        remote_fetches=1
      fi
      ;;
    mirror)
      ;;
    *)
      say_option
      ;;
  esac
  return 0
}
# remote add short options. f takes no value. t and m take a value.
# The value is the rest of the cluster, or the next word when nothing remains.
# Return 1 when the word is not a short cluster.
remote_add_short() {
  case "$1" in
    -[A-Za-z]*) ;;
    *) return 1 ;;
  esac
  # A short cluster that contains f counts as a fetch, including -tf and -ft.
  case "$1" in
    *f*) remote_fetches=1 ;;
  esac
  ra_rest=${1#-}
  while [ -n "$ra_rest" ]; do
    ra_letter=${ra_rest%"${ra_rest#?}"}
    ra_rest=${ra_rest#?}
    case "$ra_letter" in
      f)
        ;;
      t|m)
        if [ -z "$ra_rest" ]; then
          prev=skip
        fi
        return 0
        ;;
      *)
        say_option
        ;;
    esac
  done
  return 0
}
# Long options for one subcommand, from that command's git help.
# kind is flag, value, or opt. opt takes only an attached "=value".
# A unique prefix selects one option. Unknown and ambiguous spellings do not.
long_candidates() {
  case "$1" in
    clone)
      printf '%s' 'verbose:flag no-verbose:flag quiet:flag no-quiet:flag progress:flag no-progress:flag reject-shallow:flag no-reject-shallow:flag no-checkout:flag checkout:flag bare:flag no-bare:flag mirror:flag no-mirror:flag local:flag no-local:flag no-hardlinks:flag hardlinks:flag shared:flag no-shared:flag recurse-submodules:opt no-recurse-submodules:flag recursive:opt no-recursive:flag jobs:value no-jobs:flag template:value no-template:flag reference:value no-reference:flag reference-if-able:value no-reference-if-able:flag dissociate:flag no-dissociate:flag origin:value no-origin:flag branch:value no-branch:flag revision:value no-revision:flag upload-pack:value no-upload-pack:flag depth:value no-depth:flag shallow-since:value no-shallow-since:flag shallow-exclude:value no-shallow-exclude:flag single-branch:flag no-single-branch:flag tags:flag no-tags:flag shallow-submodules:flag no-shallow-submodules:flag separate-git-dir:value no-separate-git-dir:flag ref-format:value no-ref-format:flag config:value no-config:flag server-option:value no-server-option:flag ipv4:flag ipv6:flag filter:value no-filter:flag also-filter-submodules:flag no-also-filter-submodules:flag remote-submodules:flag no-remote-submodules:flag sparse:flag no-sparse:flag bundle-uri:value no-bundle-uri:flag'
      ;;
    fetch)
      printf '%s' 'verbose:flag no-verbose:flag quiet:flag no-quiet:flag all:flag no-all:flag set-upstream:flag no-set-upstream:flag append:flag no-append:flag atomic:flag no-atomic:flag upload-pack:value no-upload-pack:flag force:flag no-force:flag multiple:flag no-multiple:flag tags:flag no-tags:flag jobs:value no-jobs:flag prefetch:flag no-prefetch:flag prune:flag no-prune:flag prune-tags:flag no-prune-tags:flag recurse-submodules:opt no-recurse-submodules:flag dry-run:flag no-dry-run:flag porcelain:flag no-porcelain:flag write-fetch-head:flag no-write-fetch-head:flag keep:flag no-keep:flag update-head-ok:flag no-update-head-ok:flag progress:flag no-progress:flag depth:value no-depth:flag shallow-since:value no-shallow-since:flag shallow-exclude:value no-shallow-exclude:flag deepen:value no-deepen:flag unshallow:flag refetch:flag update-shallow:flag no-update-shallow:flag refmap:value server-option:value no-server-option:flag ipv4:flag ipv6:flag negotiation-tip:value no-negotiation-tip:flag negotiate-only:flag no-negotiate-only:flag filter:value no-filter:flag auto-maintenance:flag no-auto-maintenance:flag auto-gc:flag no-auto-gc:flag show-forced-updates:flag no-show-forced-updates:flag write-commit-graph:flag no-write-commit-graph:flag stdin:flag no-stdin:flag'
      ;;
    pull)
      printf '%s' 'verbose:flag no-verbose:flag quiet:flag no-quiet:flag progress:flag no-progress:flag recurse-submodules:opt no-recurse-submodules:flag rebase:opt no-rebase:flag stat:flag no-stat:flag compact-summary:flag no-compact-summary:flag log:opt no-log:flag signoff:opt no-signoff:flag squash:flag no-squash:flag commit:flag no-commit:flag edit:flag no-edit:flag cleanup:value no-cleanup:flag ff:flag no-ff:flag ff-only:flag verify:flag no-verify:flag verify-signatures:flag no-verify-signatures:flag autostash:flag no-autostash:flag strategy:value no-strategy:flag strategy-option:value no-strategy-option:flag gpg-sign:opt no-gpg-sign:flag allow-unrelated-histories:flag no-allow-unrelated-histories:flag all:flag no-all:flag append:flag no-append:flag upload-pack:value no-upload-pack:flag force:flag no-force:flag tags:flag no-tags:flag prune:flag no-prune:flag jobs:opt no-jobs:flag dry-run:flag no-dry-run:flag keep:flag no-keep:flag depth:value no-depth:flag shallow-since:value no-shallow-since:flag shallow-exclude:value no-shallow-exclude:flag deepen:value no-deepen:flag unshallow:flag update-shallow:flag no-update-shallow:flag refmap:value server-option:value no-server-option:flag ipv4:flag no-ipv4:flag ipv6:flag no-ipv6:flag negotiation-tip:value no-negotiation-tip:flag show-forced-updates:flag no-show-forced-updates:flag set-upstream:flag no-set-upstream:flag'
      ;;
    ls-remote)
      printf '%s' 'quiet:flag no-quiet:flag upload-pack:value no-upload-pack:flag tags:flag no-tags:flag branches:flag no-branches:flag refs:flag no-refs:flag get-url:flag no-get-url:flag sort:value no-sort:flag exit-code:flag no-exit-code:flag symref:flag no-symref:flag server-option:value no-server-option:flag'
      ;;
    sm-add)
      printf '%s' 'branch:value force:flag quiet:flag progress:flag reference:value ref-format:value dissociate:flag name:value depth:value'
      ;;
    sm-update)
      printf '%s' 'quiet:flag verbose:flag progress:flag init:flag require-init:flag remote:flag no-fetch:flag force:flag rebase:flag ref-format:value reference:value dissociate:flag merge:flag recursive:flag checkout:flag recommend-shallow:flag no-recommend-shallow:flag depth:value jobs:value single-branch:flag no-single-branch:flag filter:value'
      ;;
    *)
      ;;
  esac
}
# Sets lr_canon and lr_kind. Returns 1 when $2 is unknown or ambiguous.
long_resolve() {
  lr_canon=
  lr_kind=
  lr_hits=0
  lr_rest=$(long_candidates "$1")
  while [ -n "$lr_rest" ]; do
    case "$lr_rest" in
      *" "*)
        lr_cand=${lr_rest%% *}
        lr_rest=${lr_rest#* }
        ;;
      *)
        lr_cand=$lr_rest
        lr_rest=
        ;;
    esac
    lr_opt=${lr_cand%%:*}
    lr_k=${lr_cand#*:}
    case "$lr_opt" in
      "$2"*)
        lr_hits=$((lr_hits + 1))
        lr_canon=$lr_opt
        lr_kind=$lr_k
        ;;
    esac
  done
  [ "$lr_hits" -eq 1 ]
}
# Apply one resolved long option. arg, sv_name, sv_eq, lr_canon, and lr_kind are set.
long_apply() {
  case "$lr_canon" in
    upload-pack|exec|multiple)
      say_option
      ;;
    recurse-submodules|recursive|shallow-submodules)
      if [ "$sub" = clone ] || [ "$sub" = fetch ] || [ "$sub" = pull ]; then
        echo "git ${sub} denied: submodule path is outside the workspace" >&2
        printf '%s\n' "deny git ${sub}" >> "$log"
        exit 1
      fi
      ;;
  esac
  case "$lr_canon" in
    config|config-env)
      if [ "$sv_eq" = 1 ]; then
        url_assign "${arg#*=}"
      else
        prev=cfg
      fi
      return 0
      ;;
    origin)
      if [ "$sv_name" != origin ]; then
        say_option
      fi
      if [ "$sv_eq" = 1 ]; then
        remote_name_ok "${arg#*=}" || say_remote_name
        check_skipped "${arg#*=}"
      else
        prev=origin
      fi
      return 0
      ;;
    reference|reference-if-able|separate-git-dir|template|bundle-uri)
      if [ "$lr_kind" = flag ]; then
        if [ "$sv_eq" = 1 ]; then
          say_option
        fi
        return 0
      fi
      if [ "$sv_eq" = 1 ]; then
        vet_opt "${arg#*=}"
      else
        prev=path
      fi
      return 0
      ;;
  esac
  case "$lr_kind" in
    flag)
      if [ "$sv_eq" = 1 ]; then
        say_option
      fi
      if [ "$lr_canon" = all ]; then
        if [ "$sub" = fetch ] || [ "$sub" = pull ]; then
          contact_all=1
        fi
      fi
      ;;
    value)
      if [ "$sv_eq" = 1 ]; then
        check_skipped "${arg#*=}"
      else
        prev=skip
      fi
      ;;
    opt)
      if [ "$sv_eq" = 1 ]; then
        check_skipped "${arg#*=}"
      fi
      ;;
    *)
      say_option
      ;;
  esac
  return 0
}
# 0 when this long option belongs to a closed list and has been handled.
# 1 when this command has no closed list, so the caller keeps its own rules.
# An empty option name is left for git. clone has no object-format option;
# that exact spelling is left for git as well.
long_closed() {
  sv_body=${1#--}
  sv_name=${sv_body%%=*}
  sv_eq=0
  case "$1" in
    --*=*) sv_eq=1 ;;
  esac
  la_cmd=
  case "$sub" in
    clone) la_cmd=clone ;;
    fetch) la_cmd=fetch ;;
    pull) la_cmd=pull ;;
    ls-remote) la_cmd=ls-remote ;;
    submodule)
      case "$sm_action" in
        add) la_cmd=sm-add ;;
        update) la_cmd=sm-update ;;
      esac
      ;;
  esac
  if [ -z "$la_cmd" ]; then
    return 1
  fi
  case "$sv_name" in
    "")
      return 0
      ;;
  esac
  if [ "$la_cmd" = clone ] && [ "$sv_name" = object-format ]; then
    return 0
  fi
  case "$sv_name" in
    *[!A-Za-z0-9-]*)
      say_option
      ;;
  esac
  if ! long_resolve "$la_cmd" "$sv_name"; then
    say_option
  fi
  long_apply
  return 0
}
# 0 when $1 is a unique prefix of the remote-add option fetch.
remote_add_is_fetch() {
  rf_hits=0
  rf_hit=
  for rf_cand in fetch tags track master mirror no-fetch no-tags no-track no-master no-mirror; do
    case "$rf_cand" in
      "$1"*)
        rf_hits=$((rf_hits + 1))
        rf_hit=$rf_cand
        ;;
    esac
  done
  [ "$rf_hits" -eq 1 ] && [ "$rf_hit" = fetch ]
}
# 0 when $1 is a unique prefix of push's repo option.
push_is_repo() {
  pr_hits=0
  pr_repo=0
  for pr_cand in verbose no-verbose quiet no-quiet repo no-repo all no-all branches no-branches mirror no-mirror delete no-delete tags no-tags dry-run no-dry-run porcelain no-porcelain force no-force force-with-lease no-force-with-lease force-if-includes no-force-if-includes recurse-submodules no-recurse-submodules thin no-thin receive-pack no-receive-pack exec no-exec set-upstream no-set-upstream progress no-progress prune no-prune no-verify verify follow-tags no-follow-tags signed no-signed atomic no-atomic push-option no-push-option ipv4 ipv6; do
    case "$pr_cand" in
      "$1"*)
        pr_hits=$((pr_hits + 1))
        if [ "$pr_cand" = repo ]; then
          pr_repo=1
        fi
        ;;
    esac
  done
  [ "$pr_hits" -eq 1 ] && [ "$pr_repo" = 1 ]
}
# push positionals, and the repository named by --repo, can be a URL.
# A leading "~" is refused before git expands it.
push_tilde() {
  pt_prev=
  pt_seen=
  pt_dd=
  pt_repo=
  for arg in "$@"; do
    if [ -n "$pt_prev" ]; then
      if [ "$pt_repo" = 1 ]; then
        case "$arg" in
          ~*) say_tilde ;;
        esac
      fi
      pt_prev=
      pt_repo=
      continue
    fi
    if [ "$pt_dd" = 1 ]; then
      case "$arg" in
        ~*) say_tilde ;;
      esac
      continue
    fi
    case "$arg" in
      --*)
        # Only a unique prefix of --repo names a repository. Other "re" options do not.
        pt_body=${arg#--}
        pt_name=${pt_body%%=*}
        if push_is_repo "$pt_name"; then
          case "$arg" in
            --*=*)
              case "${arg#*=}" in
                ~*) say_tilde ;;
              esac
              ;;
            *)
              pt_prev=1
              pt_repo=1
              ;;
          esac
          continue
        fi
        ;;
    esac
    case "$arg" in
      -C|-c|--git-dir|--work-tree|--namespace|--super-prefix|--config-env|--exec-path|--config|--attr-source)
        pt_prev=1
        continue
        ;;
      --git-dir=*|--work-tree=*|--namespace=*|--super-prefix=*|--config-env=*|--exec-path=*|--config=*|--attr-source=*|-c*)
        continue
        ;;
      --receive-pack|--exec|--push-option|-o)
        pt_prev=1
        continue
        ;;
      --receive-pack=*|--exec=*|--push-option=*|-o*)
        continue
        ;;
      --)
        if [ -n "$pt_seen" ]; then
          pt_dd=1
        fi
        continue
        ;;
      -*)
        continue
        ;;
    esac
    if [ -z "$pt_seen" ]; then
      pt_seen=1
      continue
    fi
    case "$arg" in
      ~*) say_tilde ;;
    esac
  done
}
if [ "$grant" != "1" ]; then
  echo "git ${sub} denied: missing git grant" >&2
  printf '%s\n' "deny git ${sub}" >> "$log"
  exit 1
fi
if [ "$sub" = "push" ]; then
  for arg in "$@"; do
    refuse_command_opt "$arg"
  done
  push_tilde "$@"
  push_names_remote "$@" || resolve_branch_remote
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
    arg_dd=
    end_opts=
    for arg in "$@"; do
      if [ -n "$prev" ]; then
        case "$prev" in
          cfg)
            url_assign "$arg"
            ;;
          path)
            vet_opt "$arg"
            ;;
          skip)
            check_skipped "$arg"
            ;;
          origin)
            remote_name_ok "$arg" || say_remote_name
            check_skipped "$arg"
            ;;
        esac
        prev=
        continue
      fi
      # After "--", remote add, remote rename, and remote remove treat later words as names.
      # Every other command still refuses a word that starts with "-".
      if [ "$arg_dd" != 1 ]; then
      # remote add: only the options git accepts. A unique prefix is that option.
      # Anything else that is a short cluster or a long option is refused here,
      # before a name is read. A word that is not an option, including a lone "-",
      # is a positional and is checked as a name below.
      if [ "$sub" = remote ] && [ "$remote_sub" = add ]; then
        case "$arg" in
          --)
            arg_dd=1
            continue
            ;;
          --*)
            remote_add_long "$arg"
            continue
            ;;
          -[A-Za-z]*)
            remote_add_short "$arg" || say_option
            continue
            ;;
        esac
      elif [ "$end_opts" = 1 ]; then
        case "$arg" in
          -*)
            refuse_command_opt "$arg"
            refuse_submodule_opt "$arg"
            fetch_multiple_short "$arg"
            say_option
            ;;
        esac
      else
      refuse_command_opt "$arg"
      refuse_submodule_opt "$arg"
      fetch_multiple_short "$arg"
      if [ "$sub" = clone ] && clone_short "$arg"; then
        case "$arg" in
          -o?*) check_skipped "${arg#-o}" ;;
          -b?*) check_skipped "${arg#-b}" ;;
          -j?*) check_skipped "${arg#-j}" ;;
        esac
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
        --origin|-o)
          if [ "$sub" = clone ]; then
            prev=origin
          else
            prev=skip
          fi
          continue
          ;;
        -C|--git-dir|--work-tree|--namespace|--super-prefix|--exec-path|--depth|--branch|-b|--server-option|--jobs|-j|--filter|--shallow-since|--shallow-exclude|--revision)
          prev=skip
          continue
          ;;
        --origin=*)
          if [ "$sub" = clone ]; then
            remote_name_ok "${arg#*=}" || say_remote_name
          fi
          check_skipped "${arg#*=}"
          continue
          ;;
        --depth=*|--branch=*|--server-option=*|--jobs=*|--filter=*|--shallow-since=*|--shallow-exclude=*|--revision=*)
          check_skipped "${arg#*=}"
          continue
          ;;
        --git-dir=*|--work-tree=*|--namespace=*|--super-prefix=*|--exec-path=*)
          continue
          ;;
        -j*|-b*|-o*)
          case "$arg" in
            -j*) check_skipped "${arg#-j}" ;;
            -b*) check_skipped "${arg#-b}" ;;
            -o*) check_skipped "${arg#-o}" ;;
          esac
          continue
          ;;
        --)
          # remote remove still checks the name after "--". remote update does not.
          if [ "$sub" = remote ] && { [ "$remote_sub" = rename ] || [ "$remote_sub" = remove ] || [ "$remote_sub" = rm ]; }; then
            arg_dd=1
          else
            end_opts=1
          fi
          continue
          ;;
        --all)
          if [ "$sub" = fetch ] || [ "$sub" = pull ]; then
            contact_all=1
          fi
          continue
          ;;
        --*)
          if long_closed "$arg"; then
            continue
          fi
          sv_body=${arg#--}
          sv_name=${sv_body%%=*}
          # A long option that is a prefix of --origin is that option.
          # Only the exact --origin spelling is handled above. --no-origin is not a prefix.
          if [ "$sub" = clone ]; then
            case "$sv_name" in
              ""|origin|*[!A-Za-z0-9-]*) ;;
              *)
                case "origin" in
                  "$sv_name"*) say_option ;;
                esac
                ;;
            esac
          fi
          # submodule add: --name and --ref-format take a value. It is not the URL.
          # -b, --branch, --depth, -j, --jobs, --reference, and --reference-if-able
          # are consumed by the shared option lists above. A "=" form does not
          # take the next word.
          if [ "$sub" = submodule ] && [ "$sm_action" = add ]; then
            case "$sv_name" in
              name|ref-format)
                case "$arg" in
                  --*=*) check_skipped "${arg#*=}" ;;
                  *) prev=skip ;;
                esac
                continue
                ;;
            esac
          fi
          if skip_value_name "$sv_name"; then
            case "$arg" in
              --*=*)
                check_skipped "${arg#*=}"
                ;;
              *)
                prev=skip
                ;;
            esac
          fi
          continue
          ;;
        -*)
          # A new name on rename that starts with "-" is still a name.
          if [ "$sub" = remote ] && [ "$remote_sub" = rename ] && [ "$remote_npos" -ge 1 ]; then
            remote_name_ok "$arg" || say_remote_name
          fi
          continue
          ;;
      esac
      fi
      fi
      if [ -z "$seen_sub" ]; then
        seen_sub=1
        continue
      fi
      if [ "$sub" = submodule ] && [ -z "$sm_action" ]; then
        sm_action=$arg
        case "$sm_action" in
          update|init|sync|foreach|status)
            found_url=1
            ;;
        esac
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
      if [ "$sub" = remote ] && [ -n "$remote_sub" ]; then
        remote_npos=$((remote_npos + 1))
        case "$remote_sub" in
          prune|update|show)
            remote_name_ok "$arg" || say_remote_name
            ;;
          rename)
            if [ "$remote_npos" -le 2 ]; then
              remote_name_ok "$arg" || say_remote_name
            fi
            ;;
          add|set-url|get-url|remove|rm|set-head|set-branches)
            if [ "$remote_npos" -eq 1 ]; then
              remote_name_ok "$arg" || say_remote_name
            fi
            ;;
        esac
        case "$remote_sub" in
          set-head|set-branches)
            if [ "$remote_npos" -gt 1 ]; then
              continue
            fi
            ;;
        esac
      fi
      if colon_remote "$arg"; then
        if [ "$sub" = submodule ] && [ "$sm_action" = add ] && [ -z "$sm_url_set" ]; then
          case "$arg" in
            .|..|./*|../*) say_sub_rel ;;
          esac
          sm_before=$allow_file
          vet "$arg"
          sm_url_set=1
          found_url=1
          if [ "$sm_before" != 1 ] && [ "$allow_file" = 1 ]; then
            sm_url_armed=1
          fi
        elif [ "$sub" = submodule ] && [ "$sm_action" != add ]; then
          check_skipped "$arg"
        else
          vet "$arg"
          found_url=1
        fi
        continue
      fi
      case "$arg" in
        *://*|git@*)
          if [ "$sub" = submodule ] && [ "$sm_action" = add ] && [ -z "$sm_url_set" ]; then
            case "$arg" in
              .|..|./*|../*) say_sub_rel ;;
            esac
            sm_before=$allow_file
            vet "$arg"
            sm_url_set=1
            found_url=1
            if [ "$sm_before" != 1 ] && [ "$allow_file" = 1 ]; then
              sm_url_armed=1
            fi
          elif [ "$sub" = submodule ]; then
            check_skipped "$arg"
          else
            vet "$arg"
            found_url=1
          fi
          ;;
        *)
          # A leading "~" on a positional is not a workspace path.
          # This includes a slashless word and a word after "--".
          case "$arg" in
            ~*) say_tilde ;;
          esac
          if [ "$sub" = clone ]; then
            vet_local "$arg"
            found_url=1
          elif [ "$sub" = submodule ]; then
            if [ "$sm_action" = add ] && [ -z "$sm_url_set" ]; then
              case "$arg" in
                .|..|./*|../*) say_sub_rel ;;
              esac
              sm_before=$allow_file
              vet "$arg"
              sm_url_set=1
              found_url=1
              if [ "$sm_before" != 1 ] && [ "$allow_file" = 1 ]; then
                sm_url_armed=1
              fi
            else
              case "$arg" in
                /*|./*|../*|..|*/..|*/../*|*/*|.)
                  check_local_arg "$arg"
                  ;;
                *)
                  if [ -e "$vet_base/$arg" ] || [ -L "$vet_base/$arg" ]; then
                    check_local_arg "$arg"
                  fi
                  ;;
              esac
            fi
          else
            case "$arg" in
              /*|./*|../*|..|*/..|*/../*|*/*|.)
                resolve_remote "$arg"
                ;;
              *)
                # remote prune, update and show contact every named remote, so each name is read.
                case "$sub:$remote_sub" in
                  remote:prune|remote:update|remote:show)
                    remote_names="$remote_names$arg$nl"
                    ;;
                  remote:add|remote:set-url)
                    if [ -n "$pos" ]; then
                      vet "$arg"
                      found_url=1
                      continue
                    fi
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
    if [ "$contact_all" = 1 ]; then
      for r in $(list_remotes); do
        resolve_remote "$r"
      done
    elif [ "$sub" = remote ] && [ "$remote_sub" = update ] && [ -z "$remote_names" ]; then
      for r in $(list_remotes); do
        resolve_remote "$r"
      done
    elif [ "$found_url" = "0" ]; then
      if [ -n "$pos" ]; then
        resolve_remote "$pos"
      else
        case "$sub" in
          fetch|pull|ls-remote)
            resolve_branch_remote
            ;;
        esac
        if [ "$sub" = fetch ] || [ "$sub" = pull ]; then
          for r in $(list_remotes); do
            resolve_remote_check "$r"
          done
        fi
      fi
    fi
    # remote add fetches with -f, --fetch, a unique prefix of fetch, or a short cluster that contains f.
    case "$remote_sub" in
      add)
        for arg in "$@"; do
          case "$arg" in
            --*)
              rf_body=${arg#--}
              rf_name=${rf_body%%=*}
              case "$rf_name" in
                ""|*[!A-Za-z0-9-]*) ;;
                *)
                  if remote_add_is_fetch "$rf_name"; then
                    remote_fetches=1
                  fi
                  ;;
              esac
              ;;
            -[A-Za-z]*)
              case "$arg" in
                *f*) remote_fetches=1 ;;
              esac
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
# Resolve a ./ or ../ submodule URL against the superproject origin URL.
submodule_resolve_rel() {
  srr_origin=$1
  srr_rel=$2
  case "$srr_origin" in
    ""|*"$nl"*) return 1 ;;
  esac
  case "$srr_rel" in
    ""|*"$nl"*|*:*|-*) return 1 ;;
  esac
  while :; do
    case "$srr_origin" in
      */) srr_origin=${srr_origin%/} ;;
      *) break ;;
    esac
  done
  srr_scheme=
  srr_base=$srr_origin
  case "$srr_origin" in
    *://*)
      srr_scheme=${srr_origin%%://*}
      srr_base=${srr_origin#*://}
      ;;
  esac
  srr_rest=$srr_rel
  while [ -n "$srr_rest" ]; do
    srr_seg=${srr_rest%%/*}
    if [ "$srr_rest" = "$srr_seg" ]; then
      srr_rest=
    else
      srr_rest=${srr_rest#*/}
    fi
    case "$srr_seg" in
      ""|.)
        continue
        ;;
      ..)
        case "$srr_base" in
          "") return 1 ;;
          */*) srr_base=${srr_base%/*} ;;
          /*) srr_base= ;;
          *) return 1 ;;
        esac
        ;;
      *)
        if [ -z "$srr_base" ]; then
          srr_base=/$srr_seg
        else
          srr_base=$srr_base/$srr_seg
        fi
        ;;
    esac
  done
  if [ -z "$srr_base" ]; then
    return 1
  fi
  if [ -n "$srr_scheme" ]; then
    printf '%s://%s' "$srr_scheme" "$srr_base"
  else
    printf '%s' "$srr_base"
  fi
}
# Vet one submodule URL. A relative form is resolved against origin first.
# The check does not arm the file protocol.
vet_one_sub_url() {
  case "$1" in
    "") say_deny "" ;;
    .|..|./*|../*)
      vsu_origin=$(qget remote.origin.url)
      if [ -z "$vsu_origin" ]; then
        say_file
      fi
      vsu_resolved=$(submodule_resolve_rel "$vsu_origin" "$1") || say_file
      ;;
    *)
      vsu_resolved=$1
      ;;
  esac
  vsu_file=$allow_file
  vsu_bridge=$need_bridge
  vsu_found=$found_url
  vet "$vsu_resolved"
  allow_file=$vsu_file
  need_bridge=$vsu_bridge
  found_url=$vsu_found
}
vet_url_lines() {
  vul_rest=$1
  while [ -n "$vul_rest" ]; do
    case "$vul_rest" in
      *"$nl"*)
        vul_line=${vul_rest%%"$nl"*}
        vul_rest=${vul_rest#*"$nl"}
        ;;
      *)
        vul_line=$vul_rest
        vul_rest=
        ;;
    esac
    if [ -z "$vul_line" ]; then
      continue
    fi
    case "$vul_line" in
      *" "*)
        vul_url=${vul_line#* }
        ;;
      *)
        say_deny "$vul_line"
        ;;
    esac
    vet_one_sub_url "$vul_url"
  done
}
# submodule update, init, and sync copy URLs into config before they fetch.
# Vet .gitmodules and the stored submodule.*.url values first.
# Nested .gitmodules inside a submodule are not read here.
vet_submodule_urls() {
  vsu_gm=$vet_base/.gitmodules
  if [ -e "$vsu_gm" ] || [ -L "$vsu_gm" ]; then
    if [ -L "$vsu_gm" ] || [ ! -f "$vsu_gm" ]; then
      say_file
    fi
    phys_inside "$vsu_gm" || say_file
    vsu_lines=$(
      eval "set -- $gitdir_args"
      "$real" -C "$vet_base" "$@" \
        -c core.hooksPath=/dev/null \
        -c core.fsmonitor= \
        -c core.sshCommand=/bin/false \
        -c protocol.allow=never \
        -c safe.directory='*' \
        config -f "$vsu_gm" --get-regexp '^submodule\..*\.url$' 2>/dev/null
    ) || vsu_lines=
    vet_url_lines "$vsu_lines"
  fi
  vsu_lines=$(
    eval "set -- $gitdir_args"
    "$real" -C "$vet_base" "$@" \
      -c core.hooksPath=/dev/null \
      -c core.fsmonitor= \
      -c core.sshCommand=/bin/false \
      -c protocol.allow=never \
      -c safe.directory='*' \
      config --includes --get-regexp '^submodule\..*\.url$' 2>/dev/null
  ) || vsu_lines=
  vet_url_lines "$vsu_lines"
}
if [ "$sub" = init ]; then
  guard_init "$@"
fi
if [ "$sub" = submodule ]; then
  case "$sm_action" in
    update|init|sync)
      vet_submodule_urls
      ;;
  esac
fi
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
