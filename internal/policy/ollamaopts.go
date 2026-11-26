package policy

import (
	"errors"
	"fmt"
	"strings"
)

// MaxNumCtx is the largest options.num_ctx policy or a bot may set.
const MaxNumCtx = 1 << 20

// errOllamaNumCtx is a startup error. An out-of-range num_ctx fail-closes.
var errOllamaNumCtx = errors.New("ollama.num_ctx")

// OllamaModelOption is the chat options for one model name.
// A nil Think or a zero NumCtx does not override a lower layer.
type OllamaModelOption struct {
	Think  *bool
	NumCtx int
}

type ollamaModelOptDoc struct {
	Think  *bool `toml:"think" json:"think"`
	NumCtx *int  `toml:"num_ctx" json:"num_ctx"`
}

func checkNumCtx(n int) error {
	if n <= 0 || n > MaxNumCtx {
		return fmt.Errorf("%w must be from 1 to %d", errOllamaNumCtx, MaxNumCtx)
	}
	return nil
}

func (p *Policy) applyOllamaOptions(doc ollamaDoc) error {
	if p == nil {
		return nil
	}
	if doc.Think != nil {
		v := *doc.Think
		p.OllamaThink = &v
	}
	if doc.NumCtx != nil {
		if err := checkNumCtx(*doc.NumCtx); err != nil {
			return err
		}
		p.OllamaNumCtx = *doc.NumCtx
	}
	if len(doc.ModelOptions) == 0 {
		return nil
	}
	if p.OllamaModelOptions == nil {
		p.OllamaModelOptions = map[string]OllamaModelOption{}
	}
	for name, opt := range doc.ModelOptions {
		name = strings.TrimSpace(name)
		if name == "" {
			return fmt.Errorf("%w: empty model name", errOllamaNumCtx)
		}
		item := p.OllamaModelOptions[name]
		if opt.Think != nil {
			v := *opt.Think
			item.Think = &v
		}
		if opt.NumCtx != nil {
			if err := checkNumCtx(*opt.NumCtx); err != nil {
				return err
			}
			item.NumCtx = *opt.NumCtx
		}
		p.OllamaModelOptions[name] = item
	}
	return nil
}

// ResolveChatOptions applies policy per-model, then policy default, then the
// bot, then the CLI. A nil think or a zero num_ctx at a layer leaves the
// lower layer in place. The result is unset when every layer is unset.
func ResolveChatOptions(p Policy, model string, botThink *bool, botNum int, cliThink *bool, cliNum int) (*bool, int) {
	var think *bool
	num := 0
	if cliThink != nil {
		v := *cliThink
		think = &v
	}
	if cliNum > 0 {
		num = cliNum
	}
	if botThink != nil {
		v := *botThink
		think = &v
	}
	if botNum > 0 {
		num = botNum
	}
	if p.OllamaThink != nil {
		v := *p.OllamaThink
		think = &v
	}
	if p.OllamaNumCtx > 0 {
		num = p.OllamaNumCtx
	}
	if item, ok := p.OllamaModelOptions[strings.TrimSpace(model)]; ok {
		if item.Think != nil {
			v := *item.Think
			think = &v
		}
		if item.NumCtx > 0 {
			num = item.NumCtx
		}
	}
	return think, num
}
