package proxy

import (
	"net"
	"time"
)

// healthLoop периодически стучится в таргет (и в резерв, если он задан),
// пока правило запущено.
func (r *Rule) healthLoop(stopCh chan struct{}) {
	defer r.wg.Done()

	r.mu.RLock()
	interval := time.Duration(r.spec.Health.IntervalSec) * time.Second
	r.mu.RUnlock()
	if interval <= 0 {
		interval = 3 * time.Second
	}

	// Первую проверку делаем сразу, не дожидаясь тика.
	r.probeOnce()

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stopCh:
			return
		case <-t.C:
			r.probeOnce()
		}
	}
}

func (r *Rule) probeOnce() {
	r.mu.RLock()
	spec := r.spec
	r.mu.RUnlock()

	timeout := time.Duration(spec.Health.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = time.Second
	}

	r.noteProbe(true, dialOK(spec.Target.Addr(), timeout))
	if spec.Backup != nil && !spec.Backup.IsZero() {
		r.noteProbe(false, dialOK(spec.Backup.Addr(), timeout))
	}

	r.mu.Lock()
	r.lastCheck = time.Now()
	r.mu.Unlock()
}

// dialOK — живо ли, если туда постучаться TCP-хендшейком.
func dialOK(addr string, timeout time.Duration) bool {
	c, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// noteProbe скармливает результат проверки конечному автомату здоровья.
// Вызывается и из healthLoop, и из handle() — реальное соединение
// сообщает о состоянии таргета не хуже отдельной пробы.
func (r *Rule) noteProbe(primary bool, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	failAfter := r.spec.Health.FailAfter
	riseAfter := r.spec.Health.RiseAfter
	if failAfter <= 0 {
		failAfter = 2
	}
	if riseAfter <= 0 {
		riseAfter = 2
	}

	if primary {
		if ok {
			r.failStreak = 0
			r.riseStreak++
			if !r.targetUp && r.riseStreak >= riseAfter {
				r.targetUp = true
			}
		} else {
			r.riseStreak = 0
			r.failStreak++
			if r.targetUp && r.failStreak >= failAfter {
				r.targetUp = false
			}
		}
	} else {
		if ok {
			r.bkFailStrk = 0
			r.bkRiseStrk++
			if !r.backupUp && r.bkRiseStrk >= riseAfter {
				r.backupUp = true
			}
		} else {
			r.bkRiseStrk = 0
			r.bkFailStrk++
			if r.backupUp && r.bkFailStrk >= failAfter {
				r.backupUp = false
			}
		}
	}

	r.decideFailoverLocked()
}

// decideFailoverLocked переключает активный адрес. Вызывать под r.mu.
func (r *Rule) decideFailoverLocked() {
	hasBackup := r.spec.Backup != nil && !r.spec.Backup.IsZero()

	if !hasBackup {
		r.usingBackup = false
		return
	}
	if !r.spec.Health.Enabled {
		return // без health-check решение принимает только человек
	}

	switch {
	case !r.usingBackup && !r.targetUp && r.backupUp && r.spec.Health.AutoFail:
		// Основной лёг, резерв живой — уходим на резерв.
		r.usingBackup = true
	case r.usingBackup && r.targetUp && r.spec.Health.AutoBack:
		// Основной вернулся — возвращаемся.
		r.usingBackup = false
	case r.usingBackup && !r.backupUp && r.targetUp:
		// Резерв тоже отвалился, а основной жив — смысла сидеть на резерве нет.
		r.usingBackup = false
	}
}

// SwitchTo принудительно переводит правило на резерв или обратно (ручной режим).
func (r *Rule) SwitchTo(backup bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if backup && (r.spec.Backup == nil || r.spec.Backup.IsZero()) {
		return
	}
	r.usingBackup = backup
}
