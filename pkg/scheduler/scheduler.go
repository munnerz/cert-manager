package scheduler

import (
	"sync"
	"time"

	"k8s.io/utils/clock"
)

// ProcessFunc is a function to process an item in the work queue.
type ProcessFunc func(interface{})

// ScheduledWorkQueue is an interface to describe a queue that will execute the
// given ProcessFunc with the object given to Add once the time.Duration is up,
// since the time of calling Add.
type ScheduledWorkQueue interface {
	// Add will add an item to this queue, executing the ProcessFunc after the
	// Duration has come (since the time Add was called). If an existing Timer
	// for obj already exists, the previous timer will be cancelled.
	Add(interface{}, time.Duration)
	// Forget will cancel the timer for the given object, if the timer exists.
	Forget(interface{})
}

type scheduledWorkQueue struct {
	processFunc ProcessFunc
	work        map[interface{}]clock.Timer
	workLock    sync.Mutex
	clock       clock.Clock
}

// NewScheduledWorkQueue will create a new workqueue with the given processFunc
func NewScheduledWorkQueue(processFunc ProcessFunc) ScheduledWorkQueue {
	return &scheduledWorkQueue{processFunc, make(map[interface{}]clock.Timer), sync.Mutex{}, &clock.RealClock{}}
}

// Add will add an item to this queue, executing the ProcessFunc after the
// Duration has come (since the time Add was called). If an existing Timer for
// obj already exists, the previous timer will be cancelled.
func (s *scheduledWorkQueue) Add(obj interface{}, duration time.Duration) {
	// we call Forget before acquiring the workLock in order to avoid deadlock
	s.Forget(obj)
	s.workLock.Lock()
	defer s.workLock.Unlock()
	timer := s.clock.NewTimer(duration)
	s.work[obj] = timer
	go func() {
		defer s.Forget(obj)
		t := <-timer.C()
		if t.IsZero() {
			return
		}
		s.processFunc(obj)
	}()
}

// Forget will cancel the timer for the given object, if the timer exists.
func (s *scheduledWorkQueue) Forget(obj interface{}) {
	s.workLock.Lock()
	defer s.workLock.Unlock()
	if timer, ok := s.work[obj]; ok {
		timer.Stop()
		delete(s.work, obj)
	}
}
