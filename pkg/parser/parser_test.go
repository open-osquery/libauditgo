package parser

import (
	"testing"

	"github.com/open-osquery/libauditgo"
)

var (
	syscallRules = map[string]string{
		"valid_rule": `{
			"action": "always",
			"syscalls":["execve", "read"],
			"keys": ["useless_rule"],
			"filter": "exit"
		}`,

		"missing_action": `{
			"syscalls": ["execve"],
			"keys": [],
			"filter": "exit"
		}`,

		"invalid_ir": `{
			"action": "always",
			"syscalls": "something",
			"keys": ["useless_rule"],
			"filter": "exit"
		}`,

		"invalid_obj": `{
			"foo": "bar",
			"baz": ["qux"]
		}`,
	}

	fileAuditRules = map[string]string{
		"valid_rule": `{
			"path": "/etc/hosts",
			"permissions": "rwxa",
			"keys": ["file"]
		}`,

		"missing_file_path": `{
			"permissions": "rwxa",
			"keys": ["file"]
		}`,

		"missing_file_perm": `{
			"path": "/etc/hosts",
			"keys": ["file"]
		}`,
		"invalid_ir": `{
			"path": "/etc/hosts",
			"permissions": "something",
			"keys": "useless_rule"
		}`,

		"invalid_perm": `{
			"path": "/etc/hosts",
			"permissions": "something",
			"keys": ["useless_rule"]
		}`,

		"invalid_obj": `{
			"foo": "bar",
			"baz": ["qux"]
		}`,
	}
)

func TestUnmarshalFileAuditRule(t *testing.T) {
	t.Run("valid_rule", func(t *testing.T) {
		var fileRule libauditgo.FileAuditRule
		err := UnmarshalAuditRule(fileAuditRules["valid_rule"], &fileRule)
		if err != nil {
			t.Error(err)
			t.Fail()
		}

		if fileRule.Path != "/etc/hosts" ||
			fileRule.Permissions != "rwxa" ||
			fileRule.Keys[0] != "file" {
			t.Error("Missing expected field")
			t.Fail()
		}
	})

	t.Run("missing_file_path", func(t *testing.T) {
		var fileRule libauditgo.FileAuditRule
		err := UnmarshalAuditRule(fileAuditRules["missing_file_path"], &fileRule)
		if err.Error() != "Missing 'path' field" {
			t.Error(err)
			t.Fail()
		}
	})

	t.Run("missing_file_perm", func(t *testing.T) {
		var fileRule libauditgo.FileAuditRule
		err := UnmarshalAuditRule(fileAuditRules["missing_file_perm"], &fileRule)
		if err != nil {
			t.Error(err)
			t.Fail()
		}
	})

	t.Run("invalid_perm", func(t *testing.T) {
		var fileRule libauditgo.FileAuditRule
		err := UnmarshalAuditRule(fileAuditRules["invalid_perm"], &fileRule)
		if err == nil {
			// TODO [prateeknischal]: Stronger validations on the file
			// permissiosn
			// t.Error("Accepted invalid permissions")
			// t.Fail()
		}
	})

	t.Run("invalid_ir", func(t *testing.T) {
		var fileRule libauditgo.FileAuditRule
		err := UnmarshalAuditRule(fileAuditRules["invalid_ir"], &fileRule)
		if err == nil {
			t.Error("Should have failed")
			t.Fail()
		}
	})

	t.Run("invalid_obj", func(t *testing.T) {
		var fileRule libauditgo.FileAuditRule
		err := UnmarshalAuditRule(fileAuditRules["invalid_obj"], &fileRule)
		if err == nil {
			t.Error("Should have failed for invalid object")
			t.Fail()
		}
	})
}

func TestUnmarshalSyscallAuditRule(t *testing.T) {
	t.Run("valid_rule", func(t *testing.T) {
		var syscallRule libauditgo.SyscallAuditRule
		if err := UnmarshalAuditRule(
			syscallRules["valid_rule"], &syscallRule); err != nil {
			t.Error(err)
			t.Fail()
		}

		if syscallRule.Action != "always" ||
			syscallRule.Syscalls[1] != "read" ||
			syscallRule.Keys[0] != "useless_rule" ||
			syscallRule.Filter != "exit" {
			t.Error("Missing expected field")
			t.Fail()
		}
	})

	t.Run("missing_action", func(t *testing.T) {
		var syscallRule libauditgo.SyscallAuditRule
		err := UnmarshalAuditRule(syscallRules["missing_action"], &syscallRule)
		if err.Error() != "Missing 'action' field" {
			t.Error("Unexpected error message")
			t.Fail()
		}
	})

	t.Run("invalid_ir", func(t *testing.T) {
		var syscallRule libauditgo.SyscallAuditRule
		err := UnmarshalAuditRule(syscallRules["invalid_ir"], &syscallRule)
		if err == nil {
			t.Error("Should have failed")
			t.Fail()
		}
	})

	t.Run("invalid_obj", func(t *testing.T) {
		var syscallRule libauditgo.SyscallAuditRule
		err := UnmarshalAuditRule(syscallRules["invalid_obj"], &syscallRule)
		if err == nil {
			t.Error("Should have failed")
			t.Fail()
		}
	})
}
