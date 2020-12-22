package libauditgo

import (
	"bytes"
	"fmt"

	libaudit "github.com/elastic/go-libaudit"
	"github.com/lunixbochs/struc"
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
		return fmt.Errorf("failed to initialize client %s", err.Error)
	}
	err = client.AddRule(ard.toWireFormat())
	if err != nil {
		return err
	}
	return nil
}

// GetRules return a list of AuditRule representing kernel audit rules
func GetRules() ([]AuditRule, error) {
	client, err := libaudit.NewAuditClient(nil)
	defer client.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize client %s", err.Error())
	}
	rawRules, err := client.GetRules()
	if err != nil {
		return nil, fmt.Errorf("failed to get audit rules %s", err.Error())
	}
	var auditRules []AuditRule
	for _, r := range rawRules {
		var ard auditRuleData
		nbuf := bytes.NewBuffer(r)
		err = struc.Unpack(nbuf, &ard)
		if err != nil {
			return nil, fmt.Errorf("failed to process audit rule %s", err.Error())
		}
		ar, err := ard.toAuditRule()
		if err != nil {
			return nil, fmt.Errorf("failed to process audit rule %s", err.Error())
		}
		auditRules = append(auditRules, ar)
	}
	return auditRules, nil
}

// DeleteAllRules deletes all the audit rules from the kernel
func DeleteAllRules() (int, error) {
	client, err := libaudit.NewAuditClient(nil)
	defer client.Close()
	if err != nil {
		return 0, fmt.Errorf("failed to initialize client %s", err.Error())
	}
	i, err := client.DeleteRules()
	if err != nil {
		return 0, fmt.Errorf("failed to delete audit rules %s", err.Error())
	}
	return i, err
}

// DeleteRule deletes an audit rule from the kernel
func DeleteRule(rule AuditRule) error {
	client, err := libaudit.NewAuditClient(nil)
	defer client.Close()
	if err != nil {
		return fmt.Errorf("failed to initialize client %s", err.Error())
	}
	kr, _, _, err := rule.toKernelAuditRule()
	if err != nil {
		return fmt.Errorf("failed to initialize client %s", err.Error())
	}
	err = client.DeleteRule(kr.toWireFormat())
	if err != nil {
		return fmt.Errorf("failed to delete audit rule %s", err.Error())
	}
	return nil
}

// GetStatus fetches the status of the audit system
func GetStatus() (status AuditStatus, err error) {
	client, err := libaudit.NewAuditClient(nil)
	defer client.Close()
	if err != nil {
		return AuditStatus{}, fmt.Errorf("failed to initialize client %s", err.Error())
	}
	kstatus, err := client.GetStatus()
	if err != nil {
		return AuditStatus{}, fmt.Errorf("failed to get audit status %s", err.Error())
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
