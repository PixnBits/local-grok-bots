package permbroker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrClassifierEndpoint is a config error. The classifier URL must be
// loopback http or https. An enabled classifier also needs a URL.
var ErrClassifierEndpoint = errors.New("cli.permission.classifier.endpoint must be a loopback http(s) URL")

// ClassReport is one classifier reply. Checked is false when the model
// was not asked or the reply could not be used. Level is ignored unless
// it is higher than the table level.
type ClassReport struct {
	Level    Level
	Advisory string
	Checked  bool
}

// classReporter is the optional method a classifier uses to return an
// advisory. Classifiers that only implement Escalate keep the old path.
type classReporter interface {
	Classify(ctx context.Context, in ClassInput) ClassReport
}

// CheckClassifierEndpoint rejects a non-loopback URL. An empty URL is
// refused only when the classifier is enabled.
func CheckClassifierEndpoint(endpoint string, enabled bool) error {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		if enabled {
			return ErrClassifierEndpoint
		}
		return nil
	}
	if err := loopbackEndpoint(endpoint); err != nil {
		return ErrClassifierEndpoint
	}
	return nil
}

func loopbackEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return ErrClassifierEndpoint
	}
	if u.User != nil {
		return ErrClassifierEndpoint
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return ErrClassifierEndpoint
	}
	return nil
}

// LocalClassifier asks a loopback model about a redacted argv.
// It sends the tool name, the argv, and the model name. It does not
// send the environment, the raw command, or file contents.
type LocalClassifier struct {
	Endpoint string
	Model    string
	Timeout  time.Duration
	Client   *http.Client
}

// NewLocalClassifier checks the endpoint and fills a 4s timeout when
// the caller passes zero.
func NewLocalClassifier(endpoint, model string, timeout time.Duration) (*LocalClassifier, error) {
	endpoint = strings.TrimSpace(endpoint)
	if err := loopbackEndpoint(endpoint); err != nil {
		return nil, ErrClassifierEndpoint
	}
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	return &LocalClassifier{
		Endpoint: endpoint,
		Model:    strings.TrimSpace(model),
		Timeout:  timeout,
		Client:   &http.Client{Timeout: timeout},
	}, nil
}

func (c *LocalClassifier) Escalate(ctx context.Context, in ClassInput) (Level, string) {
	if c == nil {
		return "", ""
	}
	rep := c.Classify(ctx, in)
	if Rank(rep.Level) > Rank(in.Level) {
		return rep.Level, "local model raised this to " + string(rep.Level)
	}
	return "", ""
}

func (c *LocalClassifier) Classify(ctx context.Context, in ClassInput) ClassReport {
	miss := ClassReport{Advisory: "Not checked"}
	if c == nil {
		return miss
	}
	if err := loopbackEndpoint(c.Endpoint); err != nil {
		return miss
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	argv := redactArgv(in.Argv)
	if argv == nil {
		argv = []string{}
	}
	body, err := json.Marshal(struct {
		Tool  string   `json:"tool"`
		Argv  []string `json:"argv"`
		Model string   `json:"model"`
	}{
		Tool: in.Tool, Argv: argv, Model: c.Model,
	})
	if err != nil {
		return miss
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewReader(body))
	if err != nil {
		return miss
	}
	req.Header.Set("Content-Type", "application/json")
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	res, err := client.Do(req)
	if err != nil {
		return miss
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return miss
	}
	var reply struct {
		Level    string `json:"level"`
		Advisory string `json:"advisory"`
	}
	dec := json.NewDecoder(io.LimitReader(res.Body, 8192))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&reply); err != nil {
		return miss
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return miss
	}
	lvl := Level("")
	if strings.TrimSpace(reply.Level) != "" {
		parsed, ok := parseLevel(reply.Level)
		if !ok {
			return miss
		}
		lvl = parsed
	}
	return ClassReport{Level: lvl, Advisory: reply.Advisory, Checked: true}
}
