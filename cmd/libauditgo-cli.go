package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/open-osquery/libauditgo"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

var (
	app                = kingpin.New("libauditgo-cli", "A command-line app for interacting with kernel audit rules.")
	addCommand         = app.Command("add", "Add rules")
	deleteCommand      = app.Command("delete", "Delete the rules")
	listCommand        = app.Command("list", "List all the rules")
	addCommandInput    = addCommand.Arg("input", "Input file path").Required().String()
	deleteCommandInput = deleteCommand.Arg("input", "Input file path containing rules to be deleted").String()
)

func main() {
	switch kingpin.MustParse(app.Parse(os.Args[1:])) {
	// Add audit Rules
	case addCommand.FullCommand():
		addRules(*addCommandInput)
	// List audit rules
	case listCommand.FullCommand():
		printRules()
	// Delete all audit rules
	case deleteCommand.FullCommand():
		deleteRules(*deleteCommandInput)
	default:
		fmt.Fprintln(os.Stderr, "not a valid option")
		os.Exit(1)
	}
}

func addRules(filePath string) {
	rawRules, err := ioutil.ReadFile(filePath)
	if err != nil {
		fmt.Printf("failed %v", err)
		return
	}
	auditRules, err := extractAuditRules(rawRules)
	if err != nil {
		fmt.Printf("failed %v", err)
		return
	}
	success := 0
	fail := 0
	for _, rule := range auditRules {
		err := libauditgo.AddRule(rule)
		if err != nil {
			fmt.Printf("failed %v", err)
			fail++
		} else {
			success++
		}
	}
	fmt.Printf("added rules. success: %d fail: %d", success, fail)

}
func printRules() {
	auditRuleData, err := libauditgo.GetRules()
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed", err.Error())
		return
	}
	if len(auditRuleData) == 0 {
		fmt.Println("no rules")
		return
	}
	rules, err := json.MarshalIndent(auditRuleData, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed", err.Error())
		return
	}

	fmt.Println(string(rules))
}

func deleteRules(filePath string) {
	if filePath == "" {
		num, err := libauditgo.DeleteAllRules()
		if err != nil {
			fmt.Fprintln(os.Stderr, "failed", err.Error())
			return
		}
		if num > 0 {
			fmt.Printf("deleted %d rules", num)
		}
	} else {
		rawRules, err := ioutil.ReadFile(filePath)
		if err != nil {
			fmt.Printf("failed %v", err)
			return
		}
		auditRules, err := extractAuditRules(rawRules)
		if err != nil {
			fmt.Printf("failed %v", err)
			return
		}
		success := 0
		fail := 0
		for _, rule := range auditRules {
			err := libauditgo.DeleteRule(rule)
			if err != nil {
				fmt.Printf("failed %v", err)
				fail++
			} else {
				success++
			}
		}
		fmt.Printf("deleted rules. success: %d fail: %d", success, fail)
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
				return nil, fmt.Errorf("failed %v", err)
			}
			err = json.Unmarshal(buf, &afr)
			if err != nil {
				return nil, fmt.Errorf("failed %v", err)
			}
			auditRules = append(auditRules, afr)
		} else {
			afr := &libauditgo.SyscallAuditRule{}
			buf, err := json.Marshal(x)
			if err != nil {
				return nil, fmt.Errorf("failed %v", err)
			}
			err = json.Unmarshal(buf, &afr)
			if err != nil {
				return nil, fmt.Errorf("failed %v", err)
			}
			auditRules = append(auditRules, afr)
		}
	}
	return auditRules, nil
}
