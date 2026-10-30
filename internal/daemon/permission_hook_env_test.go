package daemon

import (
	"os"
	"strconv"
)

func osGetenvInt(name string) int {
	n, err := strconv.Atoi(os.Getenv(name))
	if err != nil {
		return 0
	}
	return n
}
