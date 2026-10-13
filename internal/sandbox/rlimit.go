package sandbox

import (
	"fmt"
	"strconv"
)

// Rlimits is a process resource cap. A zero field leaves that limit alone.
type Rlimits struct {
	Nofile     int
	Nproc      int
	CPUSeconds int
}

// Zero reports whether every field leaves the current limit in place.
func (r Rlimits) Zero() bool {
	return r.Nofile == 0 && r.Nproc == 0 && r.CPUSeconds == 0
}

// UnsupportedRlimits fails closed on macOS when a limit is set.
// Seatbelt has no equivalent of these process limits.
func UnsupportedRlimits(goos string, r Rlimits) error {
	if goos != "darwin" || r.Zero() {
		return nil
	}
	return fmt.Errorf("rlimits are not enforceable on macOS: Seatbelt has no equivalent")
}

// AppendBwrapRlimits inserts --rlimit NAME soft hard before the command
// separator. Soft and hard are the same value. A zero Rlimits returns args.
func AppendBwrapRlimits(args []string, r Rlimits) []string {
	if r.Zero() {
		return args
	}
	var flags []string
	if r.Nofile > 0 {
		flags = append(flags, rlimitTriple("NOFILE", r.Nofile)...)
	}
	if r.Nproc > 0 {
		flags = append(flags, rlimitTriple("NPROC", r.Nproc)...)
	}
	if r.CPUSeconds > 0 {
		flags = append(flags, rlimitTriple("CPU", r.CPUSeconds)...)
	}
	for i, arg := range args {
		if arg != "--" {
			continue
		}
		out := make([]string, 0, len(args)+len(flags))
		out = append(out, args[:i]...)
		out = append(out, flags...)
		out = append(out, args[i:]...)
		return out
	}
	return append(append([]string{}, args...), flags...)
}

func rlimitTriple(name string, n int) []string {
	s := strconv.Itoa(n)
	return []string{"--rlimit", name, s, s}
}

// SplitBwrapRlimits removes --rlimit triples that appear before the command
// separator and returns the limits they named.
func SplitBwrapRlimits(args []string) ([]string, Rlimits, error) {
	var rest []string
	var r Rlimits
	for i := 0; i < len(args); i++ {
		if args[i] == "--" {
			rest = append(rest, args[i:]...)
			break
		}
		if args[i] != "--rlimit" {
			rest = append(rest, args[i])
			continue
		}
		if i+3 >= len(args) {
			return nil, Rlimits{}, fmt.Errorf("rlimit flag is incomplete")
		}
		name := args[i+1]
		soft, err1 := strconv.Atoi(args[i+2])
		hard, err2 := strconv.Atoi(args[i+3])
		if err1 != nil || err2 != nil || soft != hard || soft < 1 {
			return nil, Rlimits{}, fmt.Errorf("rlimit %s is invalid", name)
		}
		switch name {
		case "NOFILE":
			r.Nofile = soft
		case "NPROC":
			r.Nproc = soft
		case "CPU":
			r.CPUSeconds = soft
		default:
			return nil, Rlimits{}, fmt.Errorf("rlimit %s is unknown", name)
		}
		i += 3
	}
	return rest, r, nil
}
