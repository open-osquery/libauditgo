package libauditgo

// AuditStatus represents the state of the audit system
type AuditStatus struct {
	Enabled         uint32 `json:"enabled"`           // 1 = enabled, 0 = disabled, 2 = immutable
	Failure         uint32 `json:"failure"`           // Failure-to-log action.
	PID             uint32 `json:"pid"`               // PID of auditd process.
	RateLimit       uint32 `json:"rate_limit"`        // Messages rate limit (per second).
	BacklogLimit    uint32 `json:"backlog_limit"`     // Waiting messages limit.
	Lost            uint32 `json:"lost"`              // Messages lost.
	Backlog         uint32 `json:"backlog"`           // Messages waiting in queue.
	BacklogWaitTime uint32 `json:"backlog_wait_time"` // Message queue wait timeout.
}
