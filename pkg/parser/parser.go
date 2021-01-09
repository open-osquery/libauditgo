package parser

import (
	"encoding/json"
	"errors"

	"github.com/open-osquery/libauditgo"
)

// UnmarshalAuditRule is json.Unmarshal style deserialiser that accepts a string
// that represents an audit rule in the intermediate representation (ir) and
// constructs a libauditgo.AuditRule out of it with some validations enforced.
// Sample Usage:
//  var rule libauditgo.SyscallAuditRule
//  ir := `{"syscalls": ["write", "read"], "action": "always", "filters": "exit"}`
//  UnmarshalAuditRule(ir, &rule)
func UnmarshalAuditRule(rule string, v libauditgo.AuditRule) error {
	var err error
	switch r := v.(type) {
	case *libauditgo.SyscallAuditRule:
		if err = json.Unmarshal([]byte(rule), v); err == nil {
			return validateSyscallAuditRule(r)
		}
	case *libauditgo.FileAuditRule:
		if err = json.Unmarshal([]byte(rule), v); err == nil {
			return validateFileAuditRule(r)
		}
	default:
		return errors.New("Invalid rule for serialization")
	}

	return err
}

func validateFileAuditRule(rule *libauditgo.FileAuditRule) error {
	if len(rule.Path) == 0 {
		return errors.New("Missing 'path' field")
	}

	return nil
}

func validateSyscallAuditRule(rule *libauditgo.SyscallAuditRule) error {
	if len(rule.Action) == 0 {
		return errors.New("Missing 'action' field")
	}

	if len(rule.Filter) == 0 {
		return errors.New("Require atleast one 'matching rules'")
	}

	if rule.Syscalls == nil || len(rule.Syscalls) == 0 {
		return errors.New("Missing 'syscalls' list")
	}

	return nil
}
