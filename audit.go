package libauditgo

import (
	"bytes"

	libaudit "github.com/elastic/go-libaudit"
	"github.com/lunixbochs/struc"
	"github.com/pkg/errors"
)

// AddRule adds audit rule to the kernel
func AddRule(r AuditRule) (err error) {
	ard, _, _, err := r.toKernelAuditRule()
	if err != nil {
		return
	}
	client, err := libaudit.NewAuditClient(nil)
	defer client.Close()
	if err != nil {
		return errors.Wrap(err, "Failed to initialize client")
	}
	err = client.AddRule(ard.toWireFormat())
	if err != nil {
		return errors.Wrap(err, "Failed to add rule")
	}
	return nil
}

// GetRules return a list of AuditRule representing kernel audit rules
func GetRules() ([]AuditRule, error) {
	client, err := libaudit.NewAuditClient(nil)
	defer client.Close()
	if err != nil {
		return nil, errors.Wrap(err, "Failed to initialize client")
	}
	rawRules, err := client.GetRules()
	if err != nil {
		return nil, errors.Wrap(err, "Failed to get audit rules")
	}
	var auditRules []AuditRule
	for _, r := range rawRules {
		var ard auditRuleData
		nbuf := bytes.NewBuffer(r)
		if err := struc.Unpack(nbuf, &ard); err != nil {
			return nil, errors.Wrap(err, "Failed to process audit rule")
		}
		ar, err := ard.toAuditRule()
		if err != nil {
			return nil, errors.Wrap(err, "Failed to process audit rule")
		}
		auditRules = append(auditRules, ar)
	}
	return auditRules, nil
}

// GetRawRules returns list bytes representing audit rules installed in the
// system
func GetRawRules() ([][]byte, error) {
	client, err := libaudit.NewAuditClient(nil)
	defer client.Close()
	if err != nil {
		return nil, errors.Wrap(err, "Failed to initialize client")
	}
	rawRules, err := client.GetRules()
	if err != nil {
		return nil, errors.Wrap(err, "Failed to get audit rules")
	}
	return rawRules, nil
}

// DeleteAllRules deletes all the audit rules from the kernel
func DeleteAllRules() (int, error) {
	client, err := libaudit.NewAuditClient(nil)
	defer client.Close()
	if err != nil {
		return 0, errors.Wrap(err, "Failed to initialize client")
	}
	i, err := client.DeleteRules()
	if err != nil {
		return 0, errors.Wrap(err, "Failed to delete audit rules")
	}
	return i, err
}

// DeleteRule deletes an audit rule from the kernel
func DeleteRule(rule AuditRule) error {
	client, err := libaudit.NewAuditClient(nil)
	defer client.Close()
	if err != nil {
		return errors.Wrap(err, "Failed to initialize client")
	}
	kr, _, _, err := rule.toKernelAuditRule()
	if err != nil {
		return errors.Wrap(err, "Failed to initialize client")
	}
	if err := client.DeleteRule(kr.toWireFormat()); err != nil {
		return errors.Wrap(err, "Failed to delete audit rule")
	}
	return nil
}

// GetStatus fetches the status of the audit system
func GetStatus() (status AuditStatus, err error) {
	client, err := libaudit.NewAuditClient(nil)
	defer client.Close()
	if err != nil {
		return AuditStatus{}, errors.Wrap(err, "Failed to initialize client")
	}
	kstatus, err := client.GetStatus()
	if err != nil {
		return AuditStatus{}, errors.Wrap(err, "Failed to get audit status")
	}
	status.Enabled = kstatus.Enabled
	status.Failure = kstatus.Failure
	status.PID = kstatus.PID
	status.RateLimit = kstatus.RateLimit
	status.BacklogLimit = kstatus.BacklogLimit
	status.Lost = kstatus.Lost
	status.Backlog = kstatus.Backlog
	status.BacklogWaitTime = kstatus.BacklogWaitTime
	return status, nil
}

// SetEnabled is used to toggle the audit system active/inactive
func SetEnabled(enabled bool) (err error) {
	client, err := libaudit.NewAuditClient(nil)
	defer client.Close()
	if err != nil {
		return errors.Wrap(err, "Failed to initialize client")
	}
	if err := client.SetEnabled(enabled, libaudit.WaitForReply); err != nil {
		return errors.Wrap(err, "Failed to change status")
	}
	return nil
}

// SetBacklogLimit sets max number of outstanding audit buffers
func SetBacklogLimit(limit uint32) (err error) {
	client, err := libaudit.NewAuditClient(nil)
	defer client.Close()
	if err != nil {
		return errors.Wrap(err, "Failed to initialize client")
	}
	if err := client.SetBacklogLimit(limit, libaudit.WaitForReply); err != nil {
		return errors.Wrap(err, "Failed to set backlog limit")
	}
	return nil
}
