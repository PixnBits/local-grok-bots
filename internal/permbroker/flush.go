package permbroker

func (e *Engine) flushLoop() {
	defer e.flushWG.Done()
	for {
		select {
		case <-e.stopCh:
			return
		case <-e.flushCh:
			e.flushRules()
		}
	}
}

func (e *Engine) pokeFlushLocked() {
	if e.closed || e.flushCh == nil {
		return
	}
	select {
	case e.flushCh <- struct{}{}:
	default:
	}
}

// flushRules writes rule-use updates. It holds writeMu across the write so
// a newer SaveRule cannot be replaced by an older snapshot.
func (e *Engine) flushRules() {
	if e == nil {
		return
	}
	e.writeMu.Lock()
	defer e.writeMu.Unlock()
	e.mu.Lock()
	if !e.dirty || e.rulesPath == "" {
		e.mu.Unlock()
		return
	}
	doc := cloneRules(e.rules)
	path := e.rulesPath
	e.dirty = false
	e.mu.Unlock()
	if err := saveRules(path, doc); err != nil {
		e.mu.Lock()
		e.dirty = true
		e.pokeFlushLocked()
		e.mu.Unlock()
		return
	}
	e.mu.Lock()
	if e.dirty {
		e.pokeFlushLocked()
	}
	e.mu.Unlock()
}

func cloneRules(doc rulesFile) rulesFile {
	out := rulesFile{Version: doc.Version, Rules: make([]Rule, len(doc.Rules))}
	for i, rule := range doc.Rules {
		rule.Argv = append([]string(nil), rule.Argv...)
		out.Rules[i] = rule
	}
	if out.Rules == nil {
		out.Rules = []Rule{}
	}
	return out
}
