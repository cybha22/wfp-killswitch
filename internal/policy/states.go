package policy

type KillSwitchState int

const (
	StateInitializing KillSwitchState = iota
	StateLocked
	StateUnlocked
	StateError
)

func (s KillSwitchState) String() string {
	switch s {
	case StateInitializing:
		return "INITIALIZING"
	case StateLocked:
		return "LOCKED"
	case StateUnlocked:
		return "UNLOCKED"
	case StateError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}
