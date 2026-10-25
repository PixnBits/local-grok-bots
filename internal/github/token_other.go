//go:build !unix

package github

func readTokenFile(path string) (string, error) {
	return "", errToken("read")
}
