package proxy

import (
	"sync"
	"time"
)

const maxEvents = 200

type Event struct {
	ID       uint64    `json:"id"`
	At       time.Time `json:"at"`
	RuleID   string    `json:"rule_id"`
	RuleName string    `json:"rule_name"`
	Kind     string    `json:"kind"`
	Message  string    `json:"message"`
}

type eventJournal struct {
	mu      sync.Mutex
	seq     uint64
	entries []Event
}

func (j *eventJournal) add(ruleID, ruleName, kind, message string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.seq++
	event := Event{ID: j.seq, At: time.Now(), RuleID: ruleID, RuleName: ruleName, Kind: kind, Message: message}
	if len(j.entries) == maxEvents {
		copy(j.entries, j.entries[1:])
		j.entries[len(j.entries)-1] = event
	} else {
		j.entries = append(j.entries, event)
	}
}

// Events returns an independent snapshot, newest first, including deleted rules.
func (m *Manager) Events() []Event {
	m.journal.mu.Lock()
	defer m.journal.mu.Unlock()
	result := make([]Event, len(m.journal.entries))
	for i := range result {
		result[i] = m.journal.entries[len(result)-1-i]
	}
	return result
}
