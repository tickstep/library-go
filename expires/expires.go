package expires

import (
	"fmt"
	"time"
)

type (
	Expires interface {
		IsExpires() bool
		GetExpires() time.Time
		SetExpires(e bool)
		fmt.Stringer
	}

	expires struct {
		expiresAt time.Time
		abort     bool
	}
)

func NewExpires(dur time.Duration) Expires {
	t := time.Now().Add(dur)
	return &expires{
		expiresAt: t,
	}
}

func NewExpiresAt(at time.Time) Expires {
	return &expires{
		expiresAt: at,
	}
}

func (ep *expires) GetExpires() time.Time {
	return ep.expiresAt
}

func (ep *expires) SetExpires(e bool) {
	ep.abort = e
}

func (ep *expires) IsExpires() bool {
	return ep.abort || time.Now().After(ep.expiresAt)
}

func (ep *expires) String() string {
	return fmt.Sprintf("expires at: %s, abort: %t", ep.expiresAt, ep.abort)
}
