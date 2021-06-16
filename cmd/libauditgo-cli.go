package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/open-osquery/libauditgo"
	"github.com/pkg/errors"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

var (
	app                      = kingpin.New("libauditgo-cli", "A command-line app for interacting with kernel audit rules.")
	addCommand               = app.Command("add", "Add rules")
	deleteCommand            = app.Command("delete", "Delete the rules")
	listCommand              = app.Command("list", "List all the rules")
	statusCommand            = app.Command("status", "Get the status of the audit subsystem")
	enableCommand            = app.Command("enable", "Enable/disable audit system")
	backlogLimitCommand      = app.Command("backlog", "Set the limit of the backlog buffer")
	addCommandInput          = addCommand.Arg("input", "Input file path").Required().String()
	deleteCommandInput       = deleteCommand.Arg("input", "Input file path containing rules to be deleted").String()
	enableCommandInput       = enableCommand.Arg("input", "State of the audit system true/false").Required().Bool()
	backlogLimitCommandInput = backlogLimitCommand.Arg("limit", "Limit of the backlog buffer").Required().Int()
	listCommandRawFlag       = listCommand.Flag("raw", "Lists all rules in raw format").Bool()
)

func main() {
	switch kingpin.MustParse(app.Parse(os.Args[1:])) {
	// Add audit Rules
	case addCommand.FullCommand():
		addRules(*addCommandInput)
	// List audit rules
	case listCommand.FullCommand():
		printRules(*listCommandRawFlag)
	// Delete all audit rules
	case deleteCommand.FullCommand():
		deleteRules(*deleteCommandInput)
	// Get audit subsystem status
	case statusCommand.FullCommand():
		getStatus()
	// Enable/disable audit Rules
	case enableCommand.FullCommand():
		enableSystem(*enableCommandInput)
	// Set the limit of the backlog buffer
	case backlogLimitCommand.FullCommand():
		setBacklogLimit(uint32(*backlogLimitCommandInput))
	}
}

func addRules(filePath string) {
	rawRules, err := ioutil.ReadFile(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed %s\n", err)
		return
	}
	auditRules, err := extractAuditRules(rawRules)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed %s\n", err)
		return
	}
	success := 0
	fail := 0
	for _, rule := range auditRules {
		err := libauditgo.AddRule(rule)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed %s\n", err)
			fail++
		} else {
			success++
		}
	}
	fmt.Fprintf(os.Stderr, "added rules. success: %d fail: %d\n", success, fail)

}

func printRules(printRaw bool) {
	if printRaw {
		auditRuleRawData, err := libauditgo.GetRawRules()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed %s\n", err)
			return
		}
		if len(auditRuleRawData) == 0 {
			fmt.Fprintf(os.Stderr, "No Rules found%s\n", err)
			return
		}
		for _, rawRule := range auditRuleRawData {
			fmt.Println(string(base64.RawStdEncoding.EncodeToString(rawRule)))
		}
		return
	}
	auditRuleData, err := libauditgo.GetRules()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed %s\n", err)
		return
	}
	if len(auditRuleData) == 0 {
		fmt.Fprintf(os.Stderr, "No Rules found%s\n", err)
		return
	}
	rules, err := json.MarshalIndent(auditRuleData, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed. %s\n", err.Error())
		return
	}

	fmt.Println(string(rules))
}

func deleteRules(filePath string) {
	if filePath == "" {
		num, err := libauditgo.DeleteAllRules()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed %s\n", err)
			return
		}
		if num > 0 {
			fmt.Printf("Deleted %d rules", num)
		}
	} else {
		rawRules, err := ioutil.ReadFile(filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed %s\n", err)
			return
		}
		auditRules, err := extractAuditRules(rawRules)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed %s\n", err)
			return
		}
		success := 0
		fail := 0
		for _, rule := range auditRules {
			err := libauditgo.DeleteRule(rule)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed %s\n", err)
				fail++
			} else {
				success++
			}
		}
		fmt.Printf("Deleted rules; success: %d fail: %d", success, fail)
	}

}

func getStatus() {
	auditStatus, err := libauditgo.GetStatus()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed %s\n", err)
		return
	}
	status, err := json.MarshalIndent(auditStatus, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed %s\n", err)
		return
	}
	fmt.Println(string(status))
}

func enableSystem(enable bool) {
	err := libauditgo.SetEnabled(enable)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed %s\n", err)
		return
	}
}

func setBacklogLimit(limit uint32) {
	err := libauditgo.SetBacklogLimit(limit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed %s\n", err)
		return
	}
}

func extractAuditRules(rawRules []byte) (auditRules []libauditgo.AuditRule, err error) {
	var ri []interface{}
	err = json.Unmarshal(rawRules, &ri)
	if err != nil {
		return nil, fmt.Errorf("failed %v", err)
	}
	for _, x := range ri {
		havepath := false
		for k := range x.(map[string]interface{}) {
			if k == "path" {
				havepath = true
			}
		}
		// If we found a path key, treat it as a file rule, otherwise treat it as a
		// syscall rule.
		if havepath {
			afr := &libauditgo.FileAuditRule{}
			buf, err := json.Marshal(x)
			if err != nil {
				return nil, errors.Wrap(err, "Failed to marshal file audit rules")
			}
			err = json.Unmarshal(buf, &afr)
			if err != nil {
				return nil, errors.Wrap(err, "Failed to unmarshal audit rules")
			}
			auditRules = append(auditRules, afr)
		} else {
			afr := &libauditgo.SyscallAuditRule{}
			buf, err := json.Marshal(x)
			if err != nil {
				return nil, errors.Wrap(err, "Failed to marshal syscall audit rules")
			}
			err = json.Unmarshal(buf, &afr)
			if err != nil {
				return nil, errors.Wrap(err, "Failed to unmarshal syscall audit rules")
			}
			auditRules = append(auditRules, afr)
		}
	}
	return auditRules, nil
}
