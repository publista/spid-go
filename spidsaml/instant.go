package spidsaml

import (
	"fmt"
	"time"
)

// CheckTime checks if two times are within in seconds
func CheckTime(t1s, t2s string) error {
	t1, err := time.Parse(time.RFC3339, t1s)
	if err != nil {
		return fmt.Errorf("invalid t1s %s", t1s)
	}
	t2, err := time.Parse(time.RFC3339, t2s)
	if err != nil {
		return fmt.Errorf("invalid t2s %s", t2s)
	}
	if !(t1.After(t2.Add(-2*time.Second)) && t1.Before(t2.Add(2*time.Second))) {
		return fmt.Errorf("t1s (%s) does not match t2s (%s)",
			t1s, t2s)
	}
	return nil
}
