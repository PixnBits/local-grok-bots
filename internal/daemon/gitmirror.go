package daemon

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// gitOverrides are applied on every host git command. They outrank a config
// file that was copied into the mirror by mistake. Empty values clear the key.
var gitOverrides = [][2]string{
	{"core.fsmonitor", ""},
	{"core.hooksPath", "/dev/null"},
	{"core.askPass", ""},
	{"core.bare", "true"},
	{"core.sshCommand", "/bin/false"},
	{"core.attributesFile", "/dev/null"},
	{"credential.helper", ""},
	{"gpg.program", ""},
	{"log.showSignature", "false"},
	{"diff.external", ""},
	{"http.proxy", ""},
	{"http.followRedirects", "false"},
	{"protocol.file.allow", "never"},
	{"protocol.ext.allow", "never"},
	{"safe.directory", "*"},
}

func gitFixedArgs() []string {
	args := []string{"--no-pager"}
	for _, p := range gitOverrides {
		args = append(args, "-c", p[0]+"="+p[1])
	}
	return args
}

func mirrorEnv(gitDir string) []string {
	path := os.Getenv("PATH")
	if path == "" {
		path = "/usr/bin:/bin"
	}
	env := []string{
		"PATH=" + path,
		"HOME=/nonexistent",
		"GIT_DIR=" + gitDir,
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=/bin/false",
		"SSH_ASKPASS=/bin/false",
		"GIT_ATTR_NOSYSTEM=1",
		"LANG=C",
		"LC_ALL=C",
		fmt.Sprintf("GIT_CONFIG_COUNT=%d", len(gitOverrides)),
	}
	for i, p := range gitOverrides {
		env = append(env,
			fmt.Sprintf("GIT_CONFIG_KEY_%d=%s", i, p[0]),
			fmt.Sprintf("GIT_CONFIG_VALUE_%d=%s", i, p[1]),
		)
	}
	return env
}

// execGit runs git with cwd and GIT_DIR set to the mirror. extra replaces
// environment entries with the same KEY= prefix. It does not read the
// workspace. args are the git subcommand and its arguments.
func execGit(ctx context.Context, gitDir string, extra []string, args ...string) (stdout, stderr []byte, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	full := append(gitFixedArgs(), args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	cmd.Dir = gitDir
	cmd.Env = mirrorEnv(gitDir)
	for _, e := range extra {
		key, _, ok := strings.Cut(e, "=")
		if !ok || key == "" {
			continue
		}
		prefix := key + "="
		replaced := false
		for i, cur := range cmd.Env {
			if strings.HasPrefix(cur, prefix) {
				cmd.Env[i] = e
				replaced = true
				break
			}
		}
		if !replaced {
			cmd.Env = append(cmd.Env, e)
		}
	}
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err = cmd.Run()
	return out.Bytes(), errb.Bytes(), err
}

func runGit(ctx context.Context, gitDir string, args ...string) (stdout, stderr []byte, err error) {
	return execGit(ctx, gitDir, nil, args...)
}

func mirrorLog(ctx context.Context, gitDir string, specs []pushSpec) (string, error) {
	var b strings.Builder
	for _, sp := range specs {
		if !strings.HasPrefix(sp.src, "refs/heads/") {
			return "", fmt.Errorf("refspec")
		}
		stdout, _, err := runGit(ctx, gitDir,
			"log", "-n", "20", "--stat", "--format=%h %s",
			"--no-textconv", "--no-ext-diff", "--no-show-signature",
			"--", sp.src,
		)
		if err != nil {
			return "", err
		}
		b.Write(stdout)
		if b.Len() > 0 && !strings.HasSuffix(b.String(), "\n") {
			b.WriteByte('\n')
		}
	}
	return b.String(), nil
}

func mirrorPush(ctx context.Context, gitDir, remote string, specs []pushSpec) (string, error) {
	args := []string{"-c", "protocol.version=1", "push", remote}
	for _, sp := range specs {
		if !strings.HasPrefix(sp.src, "refs/heads/") || !strings.HasPrefix(sp.dst, "refs/heads/") {
			return "", fmt.Errorf("refspec")
		}
		if strings.ContainsAny(sp.src, " \t\r\n") || strings.ContainsAny(sp.dst, " \t\r\n") {
			return "", fmt.Errorf("refspec")
		}
		args = append(args, sp.src+":"+sp.dst)
	}
	stdout, stderr, err := runGit(ctx, gitDir, args...)
	msg := string(stdout) + string(stderr)
	if err != nil {
		return msg, err
	}
	return msg, nil
}
