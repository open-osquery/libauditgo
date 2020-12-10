# libauditgo

---

libauditgo is a package written in golang for interacting with Linux Audit Framework. 

The Linux audit framework collects information about events on a Linux system. It can help track actions performed on a system. The audit framework works by listening to the event reported by the kernel and logging them to a log file. Linux audit framework can be very verbose and can enundate audit logs very fast. To controls what gets logged, audit rules are used to specify events of interest.

### Installation

To installl the libauditgo package execute the following command:

`https://github.com/open-osquery/libauditgo`

---

## Overview

auditctl is a userspace audit tool which is part of the Linux audit framework ecosystem used to add, delete and list audit rules. libauditgo provides functionality similar to auditctl to add, delete, and list audit rules but the representation of audit rule differs.

In libauditgo, *AuditRule* interface represents an audit rule. This interface has two implementations:

1. **FileAuditRule**

   FileAuditRule represents a file-watch audit rule. This is used to put a watch on a  directory (and its sub-tree recursivally) or a file.

   The following auditctl command can be used to monitor use of auditctl command itself.

   `auditctl -w /sbin/auditctl -p x -k audittools`

   The corresponding represententation of the above rule as FileAuditRule in JSON will be:

   ```json
   {
       "path": "/sbin/auditctl",
       "permissions": "x",
       "keys": [
         "audittools"
       ]
   }
   ```

2. **SyscallAuditRule**

   SyscallAuditRule represents a syscall audit rule. This rule is used to audit use of a specific syscall by a program. If in a syscall rule no syscall is specified then it defaults to all syscalls.  *all* keyword can also be used to add all syscalls to the rule.

   To see unsuccessful open calls:

   `auditctl -a exit,always -S open -F success=0 -k unsuccessful-open` 

   The corresponding represententation of the above rule as SyscallAuditRule in JSON will be:

   ```json
   {
       "action": "always",
       "filter": "exit",
       "syscalls": [
         "open"
       ],
       "fields": [
         {
           "name": "success",
           "value": 0,
           "op": "="
         }
       ],
       "keys": [
         "unsuccessful-open"
       ]
    }
   ```

   ---

   ## Usage

   ### Add a new rule

   `AddRule` can be used to add a new rule to the Linux audit framework. This function takes `AuditRule` and converts into a form understanable by the kernel before sendig to the kernel.

   **Sample**

   ```go
   field = libauditgo.Field{
   		Name:  "success",
   		Op:    "=",
   		Value: 0,
   }
   rule = libauditgo.SyscallAuditRule{
   	Action:   "exit",
   	Filter:   "always",
   	Syscalls: string["open"],
   	Fields:   Field[field],
   	Keys:     string["unsucccessful-open"],
   }
   
   err := libauditgo.AddRule(rule)
   if err != nil {
     fmt.Printf("failed: %v\n", err)
     os.Exit(1)
   }
   ```

   ### Delete all rules

   `DeleteAllRules` function can be used to delete all the audit rules from the kernel.

   **Sample**

   ```go
   num, err := libauditgo.DeleteAllRules()
   if err != nil {
   	fmt.Errorf("failed. %v\n", err)
   	os.Exit(1)
   }
   if num > 0 {
   	fmt.Printf("deleted %d rules", num)
   }
   ```

   ### Get all rules

   `GetRules` function can be used to get all the audit rules from the kernel. It returns a slice of `AuditRules`

   **Sample**

   ```go
   rulesData, err := libauditgo.GetRules()
   if err != nil {
   	fmt.Errorf("failed. %v\n", err)
   	os.Exit(1)
   }
   rules, err := json.MarshalIndent(rulesData, "", "  ")
   if err != nil {
   	fmt.Errorf("failed. %v\n", err)
   	os.Exit(1)
   }
   fmt.Println(string(rules))
   ```

   ---

   ## Command Line Interface

   `libauditgo` has a sample application which can be used to interact with Linux system and try out the library. This application is located in the cmd folder as `libauditgo-cli`

