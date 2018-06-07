package scheduler

import (
	"sync"
	"testing"
	"time"

	"k8s.io/utils/clock"
	testclock "k8s.io/utils/clock/testing"
)

func TestAdd(t *testing.T) {
	type testT struct {
		obj        string
		after      time.Duration
		stepBy     time.Duration
		shouldCall bool
	}
	tests := []testT{
		{
			obj:        "test500",
			after:      time.Millisecond * 500,
			stepBy:     time.Millisecond * 500,
			shouldCall: true,
		},
		{
			obj:        "test1000",
			after:      time.Second * 1,
			stepBy:     time.Millisecond * 1001,
			shouldCall: true,
		},
		{
			obj:        "test900",
			after:      time.Second * 1,
			stepBy:     time.Millisecond * 900,
			shouldCall: false,
		},
	}
	testStartTime := time.Date(2005, 01, 01, 0, 0, 0, 0, time.Local)
	for _, test := range tests {
		t.Run(test.obj, func(t *testing.T) {
			var executed bool
			// construct a fake clock
			fakeClock := testclock.NewFakeClock(testStartTime)
			// construct the queue under test
			queue := &scheduledWorkQueue{
				processFunc: func(obj interface{}) {
					if !test.shouldCall {
						t.Errorf("function called, but expected it to not be called")
					}
					if obj != test.obj {
						t.Errorf("expected obj '%+v' but got obj '%+v'", test.obj, obj)
					}
					executed = true
				},
				work:     map[interface{}]clock.Timer{},
				workLock: sync.Mutex{},
				clock:    fakeClock,
			}
			queue.Add(test.obj, test.after)
			fakeClock.Step(test.stepBy)
			// wait 50 milliseconds to ensure the timers have time to fire and execute
			time.Sleep(50 * time.Millisecond)
			if executed != test.shouldCall {
				t.Errorf("expected executed: %v but got %v", test.shouldCall, executed)
			}
		})
	}
}

func TestForget(t *testing.T) {
	type testT struct {
		obj    string
		after  time.Duration
		stepBy time.Duration
	}
	tests := []testT{
		{
			obj:    "test500",
			after:  time.Millisecond * 500,
			stepBy: time.Millisecond * 1000,
		},
		{
			obj:    "test1000",
			after:  time.Second * 1,
			stepBy: time.Millisecond * 1001,
		},
		{
			obj:    "test900",
			after:  time.Second * 1,
			stepBy: time.Millisecond * 900,
		},
	}
	testStartTime := time.Date(2005, 01, 01, 0, 0, 0, 0, time.Local)
	for _, test := range tests {
		t.Run(test.obj, func(t *testing.T) {
			var executed bool
			// construct a fake clock
			fakeClock := testclock.NewFakeClock(testStartTime)
			// construct the queue under test
			queue := &scheduledWorkQueue{
				processFunc: func(obj interface{}) {
					t.Errorf("function should never be called!")
					executed = true
				},
				work:     map[interface{}]clock.Timer{},
				workLock: sync.Mutex{},
				clock:    fakeClock,
			}
			queue.Add(test.obj, test.after)
			queue.Forget(test.obj)
			fakeClock.Step(test.stepBy)
			time.Sleep(50 * time.Millisecond)
			if executed {
				t.Errorf("expected function to not be executed")
			}
		})
	}
}
