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

// ollamaOptSet is one policy file's chat options. Managed and local stay
// apart until finishOllamaOptions. A nil Think or a zero num does not set
// that key.
type ollamaOptSet struct {
	think  *bool
	num    int
	models map[string]OllamaModelOption
}

func (p *Policy) applyOllamaOptions(doc ollamaDoc, trusted bool) error {
	if p == nil {
		return nil
	}
	set := &p.ollamaLocal
	if trusted {
		set = &p.ollamaManaged
	}
	if doc.Think != nil {
		v := *doc.Think
		set.think = &v
	}
	if doc.NumCtx != nil {
		if err := checkNumCtx(*doc.NumCtx); err != nil {
			return err
		}
		set.num = *doc.NumCtx
	}
	if len(doc.ModelOptions) == 0 {
		return nil
	}
	if set.models == nil {
		set.models = map[string]OllamaModelOption{}
	}
	for name, opt := range doc.ModelOptions {
		name = strings.TrimSpace(name)
		if name == "" {
			return fmt.Errorf("%w: empty model name", errOllamaNumCtx)
		}
		item := set.models[name]
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
		set.models[name] = item
	}
	return nil
}

// finishOllamaOptions folds the two files into OllamaThink, OllamaNumCtx,
// and OllamaModelOptions. For each key the order is managed per-model,
// managed default, local per-model, local default. A managed default blocks
// a local per-model value for that key only.
func (p *Policy) finishOllamaOptions() {
	if p == nil {
		return
	}
	p.OllamaThink = copyBool(p.ollamaManaged.think)
	if p.OllamaThink == nil {
		p.OllamaThink = copyBool(p.ollamaLocal.think)
	}
	p.OllamaNumCtx = p.ollamaManaged.num
	if p.OllamaNumCtx == 0 {
		p.OllamaNumCtx = p.ollamaLocal.num
	}
	names := map[string]struct{}{}
	for name := range p.ollamaManaged.models {
		names[name] = struct{}{}
	}
	for name := range p.ollamaLocal.models {
		names[name] = struct{}{}
	}
	var models map[string]OllamaModelOption
	for name := range names {
		managed := p.ollamaManaged.models[name]
		local := p.ollamaLocal.models[name]
		var item OllamaModelOption
		if managed.Think != nil {
			item.Think = copyBool(managed.Think)
		} else if p.ollamaManaged.think == nil {
			item.Think = copyBool(local.Think)
		}
		if managed.NumCtx > 0 {
			item.NumCtx = managed.NumCtx
		} else if p.ollamaManaged.num == 0 {
			item.NumCtx = local.NumCtx
		}
		if item.Think == nil && item.NumCtx == 0 {
			continue
		}
		if models == nil {
			models = map[string]OllamaModelOption{}
		}
		models[name] = item
	}
	p.OllamaModelOptions = models
}

func copyBool(b *bool) *bool {
	if b == nil {
		return nil
	}
	v := *b
	return &v
}

// ResolveChatOptions applies the combined policy, then the bot, then the CLI.
// Load combines policy as managed per-model, then managed default, then local
// per-model, then local default, separately for think and num_ctx. A nil
// think or a zero num_ctx at a layer leaves the lower layer in place. The
// result is unset when every layer is unset.
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
