package libauditgo

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/user"
	"path"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/open-osquery/libauditgo/headers"
)

// hostEndian is initialized to the byte order of the system
var hostEndian binary.ByteOrder

// init initializes the hostEndian to the byte order of the system
func init() {
	var i int32 = 0x1
	v := (*[4]byte)(unsafe.Pointer(&i))
	if v[0] == 0 {
		hostEndian = binary.BigEndian
	} else {
		hostEndian = binary.LittleEndian
	}
}

//KernelAuditRule represents audit rule as processed by the kernel
type KernelAuditRule struct {
}

// AuditRule asbstract syscall and file-watch audit rules
type AuditRule interface {
	toKernelAuditRule() (ard auditRuleData, act uint32, filt uint32, err error)
	Equals(auditRule AuditRule, ignoreFlags bool) bool
}

// FileAuditRule represents a file-watch audit rule
type FileAuditRule struct {
	Path            string   `json:"path"`
	Permissions     string   `json:"permissions"`
	Keys            []string `json:"keys"`
	StrictPathCheck bool     `json:"-"`
}

// toKernelAuditRule converts a FileAuditRule to auditAddRuleData
func (r *FileAuditRule) toKernelAuditRule() (ard auditRuleData, act uint32, filt uint32, err error) {
	ard.Buf = make([]byte, 0)

	err = ard.addWatch(r.Path, r.StrictPathCheck)
	if err != nil {
		return
	}
	err = ard.addPerms(r.Permissions)
	if err != nil {
		return
	}
	// The key value is optional for an audit; rule
	if len(r.Keys) > 0 {
		fpd := fieldPairData{
			fieldval:     strings.Join(r.Keys, "\u0001"),
			opval:        AuditEqual,
			fieldname:    "key",
			flags:        int(AuditFilterUnset),
			syscallAdded: true,
		}
		err = auditRuleFieldPairData(&ard, &fpd)
		if err != nil {
			return
		}
	}
	// For file-watch audit rule action is 'always' and filter is 'exit'
	act = AuditAlways
	filt = AuditFilterExit
	return
}

// Equals compares audit rules and returns true if they are equals else it
// return false. It also return false in case of malformed audit rule.
func (r *FileAuditRule) Equals(auditRule AuditRule, ignoreFlags bool) bool {
	ard, _, _, err := auditRule.toKernelAuditRule()
	if err != nil {
		return false
	}
	if !ard.isWatch() {
		return false
	}
	auditRule, err = ard.toAuditRule()
	if err != nil {
		return false
	}
	fAuditRule, ok := auditRule.(*FileAuditRule)
	if !ok {
		return false
	}
	ard, _, _, err = r.toKernelAuditRule()
	if err != nil {
		return false
	}
	rule, err := ard.toAuditRule()
	if err != nil {
		return false
	}
	k, ok := rule.(*FileAuditRule)
	if !ok {
		return false
	}
	return isFileAuditRuleEqual(*k, *fAuditRule, ignoreFlags)

}

// Field represents audit rule field
type Field struct {
	Name  string      `json:"name"`
	Value interface{} `json:"value"` // Can be a string or int
	Op    string      `json:"op"`
}

func (f *Field) toString() string {
	return fmt.Sprintf("%v%v%v", f.Name, f.Op, f.Value)
}

// SyscallAuditRule represents a syscall audit rule
type SyscallAuditRule struct {
	Action   string   `json:"action"`
	Filter   string   `json:"filter"`
	Syscalls []string `json:"syscalls"`
	Fields   []Field  `json:"fields"`
	Keys     []string `json:"keys"`
}

// toKernelAuditRule converts a SyscallAuditRule to auditAddRuleData
func (r *SyscallAuditRule) toKernelAuditRule() (ard auditRuleData, act uint32, filt uint32, err error) {
	var auditSyscallAdded bool
	var allSyscall bool
	ard.Buf = make([]byte, 0)
	syscallMap := headers.SysMapX64
	// iterate over all the syscall in the SyscallAuditRule
	for _, y := range r.Syscalls {
		if y == "all" {
			allSyscall = true
			continue
		}
		ival, ok := syscallMap[y]
		if !ok {
			return ard, 0, 0, fmt.Errorf("invalid syscall %v", y)
		}
		err = auditRuleSyscallData(&ard, ival)
		if err != nil {
			return
		}
		auditSyscallAdded = true
	}
	if allSyscall == true {
		for i := 0; i < AuditBitmaskSize-1; i++ {
			ard.Mask[i] = 0xFFFFFFFF
		}
	}
	// Parse action and filter
	// auditctl accepts action and filters comma separated in any order
	// e.g.
	// auditctl -a always,exit ->valid
	// auditctl -a exit,always ->valid
	act = parseAction(r.Action)
	filt = parseFilter(r.Filter)
	ard.Action = uint32(act)
	ard.Flags = uint32(filt)
	// iterate over all the fields in the audit syscall rule and break down field
	// name, operator and value(can be anything, hence represented by interface)

	for _, y := range r.Fields {
		var opval uint32
		switch y.Op {
		case "nt_eq", "!=":
			opval = AuditNotEqual
		case "gt_or_eq", ">=":
			opval = AuditGreaterThanOrEqual
		case "lt_or_eq", "<=":
			opval = AuditLessThanOrEqual
		case "and_eq", "&=":
			opval = AuditBitTest
		case "eq", "=":
			opval = AuditEqual
		case "gt", ">":
			opval = AuditGreaterThan
		case "lt", "<":
			opval = AuditLessThan
		case "and", "&":
			opval = AuditBitMaks
		}

		fpd := fieldPairData{
			fieldval:     y.Value,
			opval:        opval,
			fieldname:    y.Name,
			flags:        int(filt),
			syscallAdded: auditSyscallAdded,
		}
		err = auditRuleFieldPairData(&ard, &fpd)
		if err != nil {
			return
		}
	}

	// // The key value is optional for a file rule
	// if len(r.Keys) > 0 {
	// 	for _, key := range r.Keys {
	// 		fpd := fieldPairData{
	// 			fieldval:     key,
	// 			opval:        AuditEqual,
	// 			fieldname:    "key",
	// 			flags:        int(AuditFilterUnset),
	// 			syscallAdded: true,
	// 		}
	// 		err = auditRuleFieldPairData(&ard, &fpd)
	// 		if err != nil {
	// 			return
	// 		}
	// 	}
	// }
	if len(r.Keys) > 0 {
		fpd := fieldPairData{
			fieldval:     strings.Join(r.Keys, "\u0001"),
			opval:        AuditEqual,
			fieldname:    "key",
			flags:        int(AuditFilterUnset),
			syscallAdded: true,
		}
		err = auditRuleFieldPairData(&ard, &fpd)
		if err != nil {
			return
		}
	}
	return
}

// Equals compares audit rules and returns true if they are equals else it
// return false. It also return false in case of malformed audit rule.
func (r *SyscallAuditRule) Equals(auditRule AuditRule, ignoreFlags bool) bool {
	ard, _, _, err := auditRule.toKernelAuditRule()
	if err != nil {
		return false
	}
	kernelRule, _, _, err := r.toKernelAuditRule()
	if err != nil {
		return false
	}
	if ard.isWatch() != kernelRule.isWatch() {
		return false
	}
	rule1, err := ard.toAuditRule()
	if err != nil {
		return false
	}
	rule2, err := kernelRule.toAuditRule()
	if err != nil {
		return false
	}
	switch auditRule.(type) {
	case *FileAuditRule:
		f1, ok := rule1.(*FileAuditRule)
		if !ok {
			return false
		}
		f2, ok := rule2.(*FileAuditRule)
		if !ok {
			return false
		}
		return isFileAuditRuleEqual(*f1, *f2, ignoreFlags)
	case *SyscallAuditRule:
		s1, ok := rule1.(*SyscallAuditRule)
		if !ok {
			return false
		}
		s2, ok := rule2.(*SyscallAuditRule)
		if !ok {
			return false
		}
		return isSyscallAuditRulesEqual(*s1, *s2, ignoreFlags)
	default:
		return false
	}

	return false

}

// parseAction takes an action as string and returns its corresponding integer
// value
func parseAction(value string) (action uint32) {
	action = 4294967295
	if value == "never" {
		action = AuditNever
	} else if value == "possible" {
		action = AuditPossible
	} else if value == "always" {
		action = AuditAlways
	}
	return action
}

func parseFilter(value string) (filter uint32) {
	filter = AuditFilterUnset
	if value == "task" {
		filter = AuditFilterTask
	} else if value == "entry" {
		filter = AuditFilterEntry
	} else if value == "exit" {
		filter = AuditFilterExit
	} else if value == "user" {
		filter = AuditFilterUser
	} else if value == "exclude" {
		filter = AuditFilterExclude
	}
	return filter
}

// Collection of values required for auditRuleFieldPairData()
type fieldPairData struct {
	fieldval     interface{}
	opval        uint32
	fieldname    string
	flags        int
	syscallAdded bool
}

// auditRuleFieldPairData process the passed auditRuleData struct for passing to kernel
// according to passedfpd.fieldnames and flags
func auditRuleFieldPairData(rule *auditRuleData, fpd *fieldPairData) error {
	var (
		auditPermAdded bool
	)
	if rule.FieldCount >= (AuditMaxFields - 1) {
		return fmt.Errorf("max fields for rule exceeded")
	}

	var fieldid uint32
	for k, v := range headers.FieldMap {
		if k == fpd.fieldname {
			fieldid = uint32(v)
			break
		}
	}
	if fieldid == 0 {
		return fmt.Errorf("unknown field %v", fpd.fieldname)
	}
	if fpd.flags == int(AuditFilterExclude) && fieldid != AuditMsgType {
		return fmt.Errorf("exclude filter only valid with AuditMsgType")
	}
	rule.Fields[rule.FieldCount] = fieldid
	rule.Fieldflags[rule.FieldCount] = fpd.opval
	switch fieldid {
	case AuditUID, AuditEUID, AuditSUID, AuditFSUID, AuditLOGINUID, AuditObjUID, AuditObjGID:
		if val, isInt := fpd.fieldval.(float64); isInt {
			rule.Values[rule.FieldCount] = (uint32)(val)
		} else if val, isInt := fpd.fieldval.(uint32); isInt {
			rule.Values[rule.FieldCount] = (uint32)(val)
		} else if val, isString := fpd.fieldval.(string); isString {
			if val == "unset" {
				rule.Values[rule.FieldCount] = 4294967295
			} else {
				user, err := user.Lookup(val)
				if err != nil {
					return fmt.Errorf("bad user: %v: %v", user, err)
				}
				userID, err := strconv.Atoi(user.Uid)
				if err != nil {
					return fmt.Errorf("bad uid %v", userID)
				}
				rule.Values[rule.FieldCount] = (uint32)(userID)
			}
		} else {
			return fmt.Errorf("field value has unusable type %v", fpd.fieldval)
		}
	case AuditGID, AuditEGID, AuditSGID, AuditFSGID:
		if val, isInt := fpd.fieldval.(float64); isInt {
			rule.Values[rule.FieldCount] = (uint32)(val)
		} else if val, isInt := fpd.fieldval.(uint32); isInt {
			rule.Values[rule.FieldCount] = (uint32)(val)
		} else if val, isString := fpd.fieldval.(string); isString {
			group, err := user.LookupGroup(val)
			if err != nil {
				return fmt.Errorf("bad group: %v: %v", group, err)
			}
			groupID, err := strconv.Atoi(group.Gid)
			if err != nil {
				return fmt.Errorf("bad gid %v", groupID)
			}
			rule.Values[rule.FieldCount] = (uint32)(groupID)
		} else {
			return fmt.Errorf("field value has unusable type %v", fpd.fieldval)
		}
	case AuditExit:
		if fpd.flags != int(AuditFilterExit) {
			return fmt.Errorf("%v can only be used with exit filter list", fpd.fieldname)
		}
		if val, isInt := fpd.fieldval.(float64); isInt {
			rule.Values[rule.FieldCount] = (uint32)(val)
		} else if val, isInt := fpd.fieldval.(uint32); isInt {
			rule.Values[rule.FieldCount] = (uint32)(val)
		} else if _, isString := fpd.fieldval.(string); isString {
			return fmt.Errorf("string values unsupported for field type")
		} else {
			return fmt.Errorf("field value has unusable type %v", fpd.fieldval)
		}
	case AuditMsgType:
		if fpd.flags != int(AuditFilterMask) && fpd.flags != int(AuditFilterUser) {
			return fmt.Errorf("msgtype field can only be used with exclude filter list")
		}
		if val, isInt := fpd.fieldval.(float64); isInt {
			rule.Values[rule.FieldCount] = (uint32)(val)
		} else if val, isInt := fpd.fieldval.(uint32); isInt {
			rule.Values[rule.FieldCount] = (uint32)(val)
		} else if _, isString := fpd.fieldval.(string); isString {
			return fmt.Errorf("string values unsupported for field type")
		} else {
			return fmt.Errorf("field value has unusable type %v", fpd.fieldval)
		}
	case AuditObjUser, AuditObjRole, AuditObjType, AuditObjLevLow, AuditObjLevHigh,
		AuditWatch, AuditDir:
		// Watch & object filtering is invalid on anything but exit
		if fpd.flags != int(AuditFilterExit) {
			return fmt.Errorf("%v can only be used with exit filter list", fpd.fieldname)
		}
		if fieldid == AuditWatch || fieldid == AuditDir {
			auditPermAdded = true
		}
		fallthrough
	case AuditSubjUser, AuditSubjRole, AuditSubjType, AuditSubjSen, AuditSubjClr, AuditFilterKey:
		// If and only if a syscall is added or a permission is added then this field should be set
		if fieldid == AuditFilterKey && !(fpd.syscallAdded || auditPermAdded) {
			return fmt.Errorf("key field needs a watch or syscall given prior to it")
		}
		if val, isString := fpd.fieldval.(string); isString {
			valbyte := []byte(val)
			vlen := len(valbyte)
			if fieldid == AuditFilterKey && vlen > AuditMaxKeyLenght {
				return fmt.Errorf("max rule length exceeded")
			} else if vlen > PathMax {
				return fmt.Errorf("max rule length exceeded")
			}
			rule.Values[rule.FieldCount] = (uint32)(vlen)
			rule.Buflen = rule.Buflen + (uint32)(vlen)
			rule.Buf = append(rule.Buf, valbyte[:]...)
		} else {
			return fmt.Errorf("field value has unusable type, %v", fpd.fieldval)
		}
	case AuditArch:
		if fpd.syscallAdded == false {
			return fmt.Errorf("arch should be mentioned before syscall")
		}
		if !(fpd.opval == AuditNotEqual || fpd.opval == AuditEqual) {
			return fmt.Errorf("arch must have = or != operator")
		}
		// XXX Considers X64 only
		if _, isInt := fpd.fieldval.(float64); isInt {
			rule.Values[rule.FieldCount] = AuditARCH_X86_64
		} else if val, isInt := fpd.fieldval.(uint32); isInt {
			rule.Values[rule.FieldCount] = (uint32)(val)
		} else if _, isString := fpd.fieldval.(string); isString {
			return fmt.Errorf("string values unsupported for field type")
		} else {
			return fmt.Errorf("field value has unusable type, %v", fpd.fieldval)
		}
	case AuditPerm:
		if fpd.flags != int(AuditFilterExit) {
			return fmt.Errorf("%v can only be used with exit filter list", fpd.fieldname)
		} else if fpd.opval != AuditEqual {
			return fmt.Errorf("%v only takes = operator", fpd.fieldname)
		} else {
			if val, isString := fpd.fieldval.(string); isString {
				var (
					i, vallen int
					permval   uint32
				)
				vallen = len(val)
				if vallen > 4 {
					return fmt.Errorf("vallen too large")
				}
				lowerval := strings.ToLower(val)
				for i = 0; i < vallen; i++ {
					switch lowerval[i] {
					case 'r':
						permval |= AuditPermReadValue
					case 'w':
						permval |= AuditPermWriteValue
					case 'x':
						permval |= AuditPermExecValue
					case 'a':
						permval |= AuditPermAttrValue
					default:
						return fmt.Errorf("permission can only contain rwxa")
					}
				}
				rule.Values[rule.FieldCount] = permval
				auditPermAdded = true
			}
		}
	case AuditFileType:
		if val, isString := fpd.fieldval.(string); isString {
			if fpd.flags != int(AuditFilterExit) && fpd.flags != int(AuditFilterEntry) {
				return fmt.Errorf("%v can only be used with exit and entry filter list", fpd.fieldname)
			}
			var fileval int
			err := auditNameToFtype(val, &fileval)
			if err != nil {
				return err
			}
			rule.Values[rule.FieldCount] = uint32(fileval)
			if (int)(rule.Values[rule.FieldCount]) < 0 {
				return fmt.Errorf("unknown file type %v", fpd.fieldname)
			}
		} else {
			return fmt.Errorf("expected string but filetype found %v", fpd.fieldval)
		}
	case AuditArg0, AuditArg1, AuditArg2, AuditArg3:
		if val, isInt := fpd.fieldval.(float64); isInt {
			rule.Values[rule.FieldCount] = (uint32)(val)
		} else if val, isInt := fpd.fieldval.(uint32); isInt {
			rule.Values[rule.FieldCount] = (uint32)(val)
		} else if _, isString := fpd.fieldval.(string); isString {
			return fmt.Errorf("%v should be a number", fpd.fieldname)
		} else {
			return fmt.Errorf("field value has unusable type, %v", fpd.fieldval)
		}
	case AuditDevMajor, AuditInode, AuditSuccess:
		if fpd.flags != int(AuditFilterExit) {
			return fmt.Errorf("%v can only be used with exit filter list", fpd.fieldname)
		}
		fallthrough
	default:
		if fieldid == AuditInode {
			if !(fpd.opval == AuditNotEqual || fpd.opval == AuditEqual) {
				return fmt.Errorf("%v only takes = or != operators", fpd.fieldname)
			}
		}

		if fieldid == AuditPPID && !(fpd.flags == int(AuditFilterExit) || fpd.flags == int(AuditFilterEntry)) {
			return fmt.Errorf("%v can only be used with exit and entry filter list", fpd.fieldname)
		}

		if val, isInt := fpd.fieldval.(float64); isInt {
			if fieldid == AuditInode {
				// c version uses strtoul (in case of INODE)
				rule.Values[rule.FieldCount] = (uint32)(val)
			} else {
				// c version uses strtol
				rule.Values[rule.FieldCount] = (uint32)(val)
			}
		} else {
			return fmt.Errorf("%v should be a number", fpd.fieldval)
		}
	}
	rule.FieldCount++
	return nil
}

// auditNameToFtype converts string field names to integer values based on lookup table ftypeTab
func auditNameToFtype(name string, value *int) error {
	for k, v := range headers.Ftype {
		if k == name {
			*value = v
			return nil
		}
	}
	return fmt.Errorf("filetype %v not found", name)
}

// Kernel representation of audit rule data
type auditRuleData struct {
	Flags      uint32                   `struc:"uint32,little"` // AUDIT_PER_{TASK,CALL}, AUDIT_PREPEND
	Action     uint32                   `struc:"uint32,little"` // AUDIT_NEVER, AUDIT_POSSIBLE, AUDIT_ALWAYS
	FieldCount uint32                   `struc:"uint32,little"`
	Mask       [AuditBitmaskSize]uint32 `struc:"[64]uint32,little"` // syscall(s) affected
	Fields     [AuditMaxFields]uint32   `struc:"[64]uint32,little"`
	Values     [AuditMaxFields]uint32   `struc:"[64]uint32,little"`
	Fieldflags [AuditMaxFields]uint32   `struc:"[64]uint32,little"`
	Buflen     uint32                   `struc:"uint32,little,sizeof=Buf"` // total length of string fields
	Buf        []byte                   `struc:"[]byte,little"`            // string fields buffer
}

// Convert auditRuleData to a byte stream suitable for attachment in a netlink
// message
func (ard *auditRuleData) toWireFormat() []byte {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, hostEndian, ard.Flags)
	if err != nil {
		return nil
	}
	err = binary.Write(buf, hostEndian, ard.Action)
	if err != nil {
		return nil
	}
	err = binary.Write(buf, hostEndian, ard.FieldCount)
	if err != nil {
		return nil
	}
	err = binary.Write(buf, hostEndian, ard.Mask)
	if err != nil {
		return nil
	}
	err = binary.Write(buf, hostEndian, ard.Fields)
	if err != nil {
		return nil
	}
	err = binary.Write(buf, hostEndian, ard.Values)
	if err != nil {
		return nil
	}
	err = binary.Write(buf, hostEndian, ard.Fieldflags)
	if err != nil {
		return nil
	}
	err = binary.Write(buf, hostEndian, ard.Buflen)
	if err != nil {
		return nil
	}
	err = binary.Write(buf, hostEndian, ard.Buf)
	if err != nil {
		return nil
	}
	return buf.Bytes()
}

// isWatch returns true if a given kernel audit rule is a watch (file) rule.
func (ard *auditRuleData) isWatch() bool {
	var (
		foundPerm bool
		foundAll  = true
	)
	// Try to locate AuditPerm in the field list
	for i := 0; i < int(ard.FieldCount); i++ {
		field := ard.Fields[i] & (^uint32(AuditOperators))
		if field == AuditPerm {
			foundPerm = true
			continue
		}
		// Watch rules can only have 4 field types, if we see any others return false
		// these fields are perm, key, dir and watch
		if field != AuditPerm && field != AuditFilterKey && field != AuditDir && field != AuditWatch {
			return false
		}
	}
	// check for exit filter and all set bit mask
	if ((ard.Flags & AuditFilterMask) != AuditFilterUser) &&
		((ard.Flags & AuditFilterMask) != AuditFilterTask) &&
		((ard.Flags & AuditFilterMask) != AuditFilterExclude) {
		for i := 0; i < int(AuditBitmaskSize-1); i++ {
			if ard.Mask[i] != ^uint32(0) {
				foundAll = false
				break
			}
		}
	}

	if foundPerm && foundAll {
		return true
	}

	return false
}

func (ard *auditRuleData) toAuditRule() (AuditRule, error) {
	var (
		bufferOffset int
	)
	// parse syscall audit rule
	if !ard.isWatch() {
		rule := &SyscallAuditRule{
			Action: actionToName(ard.Action),
			Filter: flagToName(ard.Flags),
			Fields: make([]Field, 0),
			Keys:   make([]string, 0),
		}
		syscalls, _ := getSyscallNames(ard)
		rule.Syscalls = syscalls
		for i := 0; i < int(ard.FieldCount); i++ {
			op := (ard.Fieldflags[i] & uint32(AuditOperators))
			field := (ard.Fields[i] & (^uint32(AuditOperators)))
			fieldName := fieldToName(field)
			operator := operatorToSymbol(op)
			f := Field{
				Name:  fieldName,
				Op:    operator,
				Value: ard.Values[i],
			}
			if field == AuditArch {
				if runtime.GOARCH == "amd64" {
					f.Value = "b64"
				} else if runtime.GOARCH == "386" {
					f.Value = "b32"
				} else {
					f.Value = fmt.Sprintf("0x%X", field)
				}
			} else if field == AuditMsgType {
				//TODO https://github.com/linux-audit/audit-userspace/blob/master/lib/libaudit.h
				//TODO
				// if strings.HasPrefix(auditConstant(rule.Values[i]).String(), "auditConstant") {
				// 	result += fmt.Sprintf(" f%d%s%d", rule.Fields[i], operatorToSymbol(op), rule.Values[i])
				// } else {
				//TODO
				// result += fmt.Sprintf(" -F %s%s%s", fieldName, operatorToSymbol(op),
				// 	auditConstant(rule.Values[i]).String()[6:])
			} else if (field >= AuditSubjUser && field <= AuditObjLevHigh) && field != AuditPPID {
				// rule.Values[i] denotes the length of the buffer for the field
				f.Value = string(ard.Buf[bufferOffset : bufferOffset+int(ard.Values[i])])
			} else if field == AuditWatch || field == AuditDir || field == AuditExe {
				f.Value = string(ard.Buf[bufferOffset : bufferOffset+int(ard.Values[i])])
				bufferOffset += int(ard.Values[i])
			} else if field == AuditFilterKey {
				key := fmt.Sprintf("%s", string(ard.Buf[bufferOffset:bufferOffset+int(ard.Values[i])]))
				bufferOffset += int(ard.Values[i])
				// check for presense of multiple keys
				keyList := strings.Split(key, "\u0001")
				for _, k := range keyList {
					rule.Keys = append(rule.Keys, k)
				}
			} else if field == AuditPerm {
				var perms string
				if (ard.Values[i] & uint32(AuditPermReadValue)) > 0 {
					perms += "r"
				}
				if (ard.Values[i] & uint32(AuditPermWriteValue)) > 0 {
					perms += "w"
				}
				if (ard.Values[i] & uint32(AuditPermExecValue)) > 0 {
					perms += "x"
				}
				if (ard.Values[i] & uint32(AuditPermAttrValue)) > 0 {
					perms += "a"
				}
				f.Value = perms
			} else if field == AuditInode {
				f.Value = ard.Values[i]
			} else if field == AuditFieldCompare {
				// TODO
				// result += printFieldCmp(ard.Values[i], op)
			} else if field == AuditExit {
				// in this case rule.Values[i] holds the error code for EXIT
				// therefore it will need a audit_errno_to_name() function that peeks on error codes
				// but error codes are widely varied and printExit() function only matches 0 => success
				// so we are directly printing the integer error code in the rule
				// and not their string equivalents
				f.Value = int(ard.Values[i])
			} else {
				f.Value = ard.Values[i]
			}
			if field != AuditFilterKey {
				rule.Fields = append(rule.Fields, f)
			}
		}
		return rule, nil
	} else {
		rule := &FileAuditRule{
			Keys: make([]string, 0),
		}
		for i := 0; i < int(ard.FieldCount); i++ {
			field := (ard.Fields[i] & (^uint32(AuditOperators)))
			if field == AuditWatch || field == AuditDir {
				rule.Path = string(ard.Buf[bufferOffset : bufferOffset+int(ard.Values[i])])
				bufferOffset += int(ard.Values[i])
			} else if field == AuditFilterKey {
				key := fmt.Sprintf("%s", string(ard.Buf[bufferOffset:bufferOffset+int(ard.Values[i])]))
				bufferOffset += int(ard.Values[i])
				// check for presense of multiple keys
				keyList := strings.Split(key, "\u0001")
				for _, k := range keyList {
					rule.Keys = append(rule.Keys, k)
				}
			} else if field == AuditPerm {
				var perms string
				if (ard.Values[i] & uint32(AuditPermReadValue)) > 0 {
					perms += "r"
				}
				if (ard.Values[i] & uint32(AuditPermWriteValue)) > 0 {
					perms += "w"
				}
				if (ard.Values[i] & uint32(AuditPermExecValue)) > 0 {
					perms += "x"
				}
				if (ard.Values[i] & uint32(AuditPermAttrValue)) > 0 {
					perms += "a"
				}
				rule.Permissions = perms
			}
		}
		return rule, nil
	}
}

// printRule returns the string representation of a given kernel audit rule as
// would be printed by the auditctl utility.
func (ard *auditRuleData) printRule() string {
	var (
		watch        = ard.isWatch()
		result, n    string
		bufferOffset int
		count        int
		sys          int
		printed      bool
	)
	// parse syscall audit rule
	if !watch {
		result = fmt.Sprintf("-a %v,%v", actionToName(ard.Action), flagToName(ard.Flags))
		for i := 0; i < int(ard.FieldCount); i++ {
			field := ard.Fields[i] & (^uint32(AuditOperators))
			if field == AuditArch {
				op := ard.Fieldflags[i] & uint32(AuditOperators)
				result += fmt.Sprintf("-F arch%v", operatorToSymbol(op))
				// Determine architecture from the runtime package rather than
				// looking in a lookup table as auditd does
				if runtime.GOARCH == "amd64" {
					result += "b64"
				} else if runtime.GOARCH == "386" {
					result += "b32"
				} else {
					result += fmt.Sprintf("0x%X", field)
				}
				break
			}
		}
		n, count, sys, printed = printSyscallRule(ard)
		if printed {
			result += n
		}

	}
	for i := 0; i < int(ard.FieldCount); i++ {
		op := (ard.Fieldflags[i] & uint32(AuditOperators))
		field := (ard.Fields[i] & (^uint32(AuditOperators)))
		if field == AuditArch {
			continue
		}
		fieldName := fieldToName(field)
		if len(fieldName) == 0 {
			// unknown field
			result += fmt.Sprintf(" f%v%v%v", ard.Fields[i], operatorToSymbol(op), ard.Values[i])
			continue
		}
		// Special cases to print the different field types
		if field == AuditMsgType {
			if strings.HasPrefix(auditConstant(ard.Values[i]).String(), "auditConstant") {
				result += fmt.Sprintf(" f%d%s%d", ard.Fields[i], operatorToSymbol(op), ard.Values[i])
			} else {
				result += fmt.Sprintf(" -F %s%s%s", fieldName, operatorToSymbol(op),
					auditConstant(ard.Values[i]).String()[6:])
			}
		} else if (field >= AuditSubjUser && field <= AuditObjLevHigh) && field != AuditPPID {
			// rule.Values[i] denotes the length of the buffer for the field
			result += fmt.Sprintf(" -F %s%s%s", fieldName, operatorToSymbol(op),
				string(ard.Buf[bufferOffset:bufferOffset+int(ard.Values[i])]))
		} else if field == AuditWatch {
			if watch {
				result += fmt.Sprintf("-w %s",
					string(ard.Buf[bufferOffset:bufferOffset+int(ard.Values[i])]))
			} else {
				result += fmt.Sprintf(" -F path=%s",
					string(ard.Buf[bufferOffset:bufferOffset+int(ard.Values[i])]))
			}
			bufferOffset += int(ard.Values[i])
		} else if field == AuditDir {
			if watch {
				result += fmt.Sprintf("-w %s",
					string(ard.Buf[bufferOffset:bufferOffset+int(ard.Values[i])]))
			} else {
				result += fmt.Sprintf(" -F dir=%s",
					string(ard.Buf[bufferOffset:bufferOffset+int(ard.Values[i])]))
			}
			bufferOffset += int(ard.Values[i])
		} else if field == AuditExe {
			result += fmt.Sprintf(" -F exe=%s", string(ard.Buf[bufferOffset:bufferOffset+int(ard.Values[i])]))
			bufferOffset += int(ard.Values[i])
		} else if field == AuditFilterKey {
			key := fmt.Sprintf("%s", string(ard.Buf[bufferOffset:bufferOffset+int(ard.Values[i])]))
			bufferOffset += int(ard.Values[i])
			// checking for multiple keys
			keyList := strings.Split(key, "\u0001")
			for _, k := range keyList {
				if watch {
					result += fmt.Sprintf(" -k %s", k)
				} else {
					result += fmt.Sprintf(" -F key=%s", k)
				}
			}
		} else if field == AuditPerm {
			var perms string
			if (ard.Values[i] & uint32(AuditPermReadValue)) > 0 {
				perms += "r"
			}
			if (ard.Values[i] & uint32(AuditPermWriteValue)) > 0 {
				perms += "w"
			}
			if (ard.Values[i] & uint32(AuditPermExecValue)) > 0 {
				perms += "x"
			}
			if (ard.Values[i] & uint32(AuditPermAttrValue)) > 0 {
				perms += "a"
			}
			if watch {
				result += fmt.Sprintf(" -p %s", perms)
			} else {
				result += fmt.Sprintf(" -F perm=%s", perms)
			}
		} else if field == AuditInode {
			result += fmt.Sprintf(" -F %s%s%d", fieldName, operatorToSymbol(op), ard.Values[i])
		} else if field == AuditFieldCompare {
			result += printFieldCmp(ard.Values[i], op)
		} else if field >= AuditArg0 && field <= AuditArg3 {
			var a0, a1 int
			if field == AuditArg0 {
				a0 = int(ard.Values[i])
			} else if field == AuditArg1 {
				a1 = int(ard.Values[i])
			}
			if count > 1 {
				result += fmt.Sprintf(" -F %s%s0x%X", fieldName, operatorToSymbol(op), ard.Values[i])
			} else {
				// we try to parse the argument passed so we need the syscall found earlier
				var r = record{syscallNum: fmt.Sprintf("%d", sys), a0: a0, a1: a1}
				// record{syscallNum: fmt.Sprintf("%d", sys), a0: a0, a1: a1}
				fmt.Print(r)
				// n, err := interpretField("syscall", fmt.Sprintf("%x", ard.Values[i]), AuditSyscall, r)
				// if err != nil {
				// 	continue
				// }
				// result += fmt.Sprintf(" -F %s%s0x%X", fieldName, operatorToSymbol(op), n)
			}
		} else if field == AuditExit {
			// in this case rule.Values[i] holds the error code for EXIT
			// therefore it will need a audit_errno_to_name() function that peeks on error codes
			// but error codes are widely varied and printExit() function only matches 0 => success
			// so we are directly printing the integer error code in the rule
			// and not their string equivalents
			result += fmt.Sprintf(" -F %s%s%d", fieldName, operatorToSymbol(op), int(ard.Values[i]))
		} else {
			result += fmt.Sprintf(" -F %s%s%d", fieldName, operatorToSymbol(op), ard.Values[i])
		}

	}
	return result
}

func (ard *auditRuleData) addWatch(path string, strictCheck bool) error {
	err := checkPath(path)
	if err != nil {
		return err
	}
	path = sanitizePath(path)
	fInfo, err := os.Stat(path)
	if err != nil {
		// validate if path exists
		if os.IsNotExist(err) && strictCheck {
			return err
		}
		if !os.IsNotExist(err) {
			return err
		}
		// Otherwise the path did not exist, return an error indicating this rule
		// is being skipped
		return fmt.Errorf("skipping rule: %v", err)
	}
	// set the audit type name to either AuditWatch or AuditDir base on weather the path in
	// rule is for a file or directory
	typeName := AuditWatch
	if fInfo.IsDir() {
		typeName = AuditDir
	}

	// Verify there are no field set for the rule
	if ard.FieldCount != 0 {
		return fmt.Errorf("audit rule data is not empty and contains are %d fields", ard.FieldCount)
	}

	// set the flags and action
	ard.Flags = uint32(AuditFilterExit)
	ard.Action = uint32(AuditAlways)
	// mark all bits as would be done by audit_rule_syscallbyname_data(rule, "all")
	// refrence: https://github.com/linux-audit/audit-userspace/blob/06925edb8068c1a7b60fd51b086ce6757880b689/lib/libaudit.c#L965
	for i := 0; i < AuditBitmaskSize-1; i++ {
		ard.Mask[i] = 0xFFFFFFFF
	}
	// Now for file we will set tow field flags
	// 1. AuditWatch or AuditDir based on weather the path is a file or directory
	// 2. AuditPerm: add Read, Write, Execute and Attribute change permission by default
	ard.FieldCount = uint32(2)
	ard.Fields[0] = uint32(typeName)

	ard.Fieldflags[0] = uint32(AuditEqual)
	valbyte := []byte(path)
	vlen := len(valbyte)

	ard.Values[0] = (uint32)(vlen)
	ard.Buflen = (uint32)(vlen)
	// Now write the key value in the rule buffer space
	ard.Buf = append(ard.Buf, valbyte...)

	ard.Fields[1] = uint32(AuditPerm)
	ard.Fieldflags[1] = uint32(AuditEqual)
	ard.Values[1] = uint32(AuditPermReadValue | AuditPermWriteValue | AuditPermExecValue | AuditPermAttrValue)
	return nil
}

// addPerms parses a permissions string and associated it with a watch rule
func (ard *auditRuleData) addPerms(perms string) error {
	if len(perms) > 4 || len(perms) < 1 {
		return fmt.Errorf("invalid permission string %q", perms)
	}
	perms = strings.ToLower(perms)
	var permValue int
	for _, val := range perms {
		switch val {
		case 'r':
			permValue |= AuditPermReadValue
		case 'w':
			permValue |= AuditPermWriteValue
		case 'x':
			permValue |= AuditPermExecValue
		case 'a':
			permValue |= AuditPermAttrValue
		default:
			return fmt.Errorf("unknown permission %v", val)
		}
	}
	// it is assumed that AuditWatch or AuditDir flags have been set
	if ard.FieldCount < 1 {
		return fmt.Errorf("rule is empty")
	}

	// First see if we have an entry we are updating
	for i := range ard.Fields {
		if ard.Fields[i] == uint32(AuditPerm) {
			ard.Values[i] = uint32(permValue)
			return nil
		}
	}
	// If not check to see if we have room to add a field
	if ard.FieldCount >= AuditMaxFields-1 {
		return fmt.Errorf("maximum field limit reached")
	}

	ard.Fields[ard.FieldCount] = uint32(AuditPerm)
	ard.Values[ard.FieldCount] = uint32(permValue)
	ard.Fieldflags[ard.FieldCount] = uint32(AuditEqual)
	ard.FieldCount++

	return nil
}

// checkPath checks the path which is being used in a watch rule (AUDIT_WATCH and AUDIT_DIR) to validate it is formatted
// correctly
func checkPath(rulePath string) error {
	if len(rulePath) == 0 {
		return fmt.Errorf("path is empty")
	}
	if len(rulePath) >= PathMax {
		return fmt.Errorf("path %q too large", rulePath)
	}
	if rulePath[0] != '/' {
		return fmt.Errorf("path %q must be absolute", rulePath)
	}
	if strings.Contains(rulePath, "..") {
		return fmt.Errorf("path %q cannot contain special directory values", rulePath)
	}

	base := path.Base(rulePath)
	if len(base) > syscall.NAME_MAX {
		return fmt.Errorf("base name %q too large", base)
	}

	return nil
}

// auditRuleSyscallData makes changes in the rule struct according to system call number
func auditRuleSyscallData(rule *auditRuleData, scall int) error {
	word := auditWord(scall)
	bit := auditBit(scall)

	if word >= AuditBitmaskSize-1 {
		return fmt.Errorf("word size greater than audit bitmask size")
	}
	rule.Mask[word] |= bit
	return nil
}

func auditWord(nr int) uint32 {
	word := (uint32)((nr) / 32)
	return (uint32)(word)
}

func auditBit(nr int) uint32 {
	bit := 1 << ((uint32)(nr) - auditWord(nr)*32)
	return (uint32)(bit)
}

// sanitizePath cleans up the path in the rule definition.
// For now it only removes trainling back-slash
func sanitizePath(path string) string {
	path = strings.TrimRight(path, "/")
	return path
}

// actionToName converts an integer action value to its string counterpart
func actionToName(action uint32) string {
	return actionLookup[action]
}

// flagToName converts an integer flag value to its string counterpart
func flagToName(flag uint32) string {
	return flagLookup[flag]
}

// operatorToSymbol converts integer operator value to its symbolic string
func operatorToSymbol(op uint32) string {
	return opLookup[op]
}

// printSyscallRule returns syscall rule specific string output for rule
func printSyscallRule(ard *auditRuleData) (string, int, int, bool) {
	var (
		name    string
		all     = true
		count   int
		syscall int
		i       int
	)

	/* Rules on the following filters do not take a syscall */
	if ((ard.Flags & AuditFilterMask) == AuditFilterUser) ||
		((ard.Flags & AuditFilterMask) == AuditFilterTask) ||
		((ard.Flags & AuditFilterMask) == AuditFilterExclude) {
		return name, count, syscall, false
	}

	/* See if its all or specific syscalls */
	for i = 0; i < (AuditBitmaskSize - 1); i++ {
		if ard.Mask[i] != ^uint32(0) {
			all = false
			break
		}
	}

	if all {
		name += fmt.Sprintf(" -S all")
		count = i
		return name, count, syscall, true
	}

	for i = 0; i < AuditBitmaskSize*32; i++ {
		word := auditWord(i)
		bit := auditBit(i)
		if (ard.Mask[word] & bit) > 0 {
			n, err := syscallToName(fmt.Sprintf("%d", i))
			if len(name) == 0 {
				name += fmt.Sprintf(" -S ")
			}
			if count > 0 {
				name += ","
			}
			if err != nil {
				name += fmt.Sprintf("%d", i)
			} else {
				name += n
			}
			count++
			// we set the syscall to the last occuring one
			// behaviour is same as print_syscall() in auditctl-listing.c
			syscall = i
		}
	}
	return name, count, syscall, true
}

func getSyscallNames(ard *auditRuleData) ([]string, bool) {
	var (
		syscalls []string
		all      = true
	)

	/* Rules on the following filters do not take a syscall */
	if ((ard.Flags & AuditFilterMask) == AuditFilterUser) ||
		((ard.Flags & AuditFilterMask) == AuditFilterTask) ||
		((ard.Flags & AuditFilterMask) == AuditFilterExclude) {
		return syscalls, false
	}
	/* See if its all or specific syscalls */
	for i := 0; i < (AuditBitmaskSize - 1); i++ {
		if ard.Mask[i] != ^uint32(0) {
			all = false
			break
		}
	}
	if all {
		syscalls = append(syscalls, "all")
		return syscalls, true
	}
	for i := 0; i < AuditBitmaskSize*32; i++ {
		word := auditWord(i)
		bit := auditBit(i)
		if (ard.Mask[word] & bit) > 0 {
			n, err := syscallToName(fmt.Sprintf("%d", i))
			if err != nil {
				syscalls = append(syscalls, fmt.Sprintf("%d", i))
			} else {
				syscalls = append(syscalls, n)
			}
		}
	}
	return syscalls, true
}

// fieldToName returns a field string given its integer representation
func fieldToName(field uint32) string {
	var name string
	name = fieldLookup[int(field)]
	return name
}

// printFieldCmp returns a string denoting the comparison between the field values
func printFieldCmp(value, op uint32) string {
	var result string

	switch auditConstant(value) {
	case AUDIT_COMPARE_UID_TO_OBJ_UID:
		result = fmt.Sprintf(" -C uid%sobj_uid", operatorToSymbol(op))
	case AUDIT_COMPARE_GID_TO_OBJ_GID:
		result = fmt.Sprintf(" -C gid%sobj_gid", operatorToSymbol(op))
	case AUDIT_COMPARE_EUID_TO_OBJ_UID:
		result = fmt.Sprintf(" -C euid%sobj_uid", operatorToSymbol(op))
	case AUDIT_COMPARE_EGID_TO_OBJ_GID:
		result = fmt.Sprintf(" -C egid%sobj_gid", operatorToSymbol(op))
	case AUDIT_COMPARE_AUID_TO_OBJ_UID:
		result = fmt.Sprintf(" -C auid%sobj_uid", operatorToSymbol(op))
	case AUDIT_COMPARE_SUID_TO_OBJ_UID:
		result = fmt.Sprintf(" -C suid%sobj_uid", operatorToSymbol(op))
	case AUDIT_COMPARE_SGID_TO_OBJ_GID:
		result = fmt.Sprintf(" -C sgid%sobj_gid", operatorToSymbol(op))
	case AUDIT_COMPARE_FSUID_TO_OBJ_UID:
		result = fmt.Sprintf(" -C fsuid%sobj_uid", operatorToSymbol(op))
	case AUDIT_COMPARE_FSGID_TO_OBJ_GID:
		result = fmt.Sprintf(" -C fsgid%sobj_gid", operatorToSymbol(op))
	case AUDIT_COMPARE_UID_TO_AUID:
		result = fmt.Sprintf(" -C uid%sauid", operatorToSymbol(op))
	case AUDIT_COMPARE_UID_TO_EUID:
		result = fmt.Sprintf(" -C uid%seuid", operatorToSymbol(op))
	case AUDIT_COMPARE_UID_TO_FSUID:
		result = fmt.Sprintf(" -C uid%sfsuid", operatorToSymbol(op))
	case AUDIT_COMPARE_UID_TO_SUID:
		result = fmt.Sprintf(" -C uid%ssuid", operatorToSymbol(op))
	case AUDIT_COMPARE_AUID_TO_FSUID:
		result = fmt.Sprintf(" -C auid%sfsuid", operatorToSymbol(op))
	case AUDIT_COMPARE_AUID_TO_SUID:
		result = fmt.Sprintf(" -C auid%ssuid", operatorToSymbol(op))
	case AUDIT_COMPARE_AUID_TO_EUID:
		result = fmt.Sprintf(" -C auid%seuid", operatorToSymbol(op))
	case AUDIT_COMPARE_EUID_TO_SUID:
		result = fmt.Sprintf(" -C euid%ssuid", operatorToSymbol(op))
	case AUDIT_COMPARE_EUID_TO_FSUID:
		result = fmt.Sprintf(" -C euid%sfsuid", operatorToSymbol(op))
	case AUDIT_COMPARE_SUID_TO_FSUID:
		result = fmt.Sprintf(" -C suid%sfsuid", operatorToSymbol(op))
	case AUDIT_COMPARE_GID_TO_EGID:
		result = fmt.Sprintf(" -C gid%segid", operatorToSymbol(op))
	case AUDIT_COMPARE_GID_TO_FSGID:
		result = fmt.Sprintf(" -C gid%sfsgid", operatorToSymbol(op))
	case AUDIT_COMPARE_GID_TO_SGID:
		result = fmt.Sprintf(" -C gid%ssgid", operatorToSymbol(op))
	case AUDIT_COMPARE_EGID_TO_FSGID:
		result = fmt.Sprintf(" -C egid%sfsgid", operatorToSymbol(op))
	case AUDIT_COMPARE_EGID_TO_SGID:
		result = fmt.Sprintf(" -C egid%ssgid", operatorToSymbol(op))
	case AUDIT_COMPARE_SGID_TO_FSGID:
		result = fmt.Sprintf(" -C sgid%sfsgid", operatorToSymbol(op))
	}

	return result
}

// syscallToName takes syscall number and returns the syscall name.
func syscallToName(syscall string) (string, error) {
	syscallMap := headers.ReverseSysMapX64
	if val, ok := syscallMap[syscall]; ok {
		return val, nil
	}
	return "", fmt.Errorf("syscall %v not found", syscall)
}

func isFileAuditRuleEqual(rule1 FileAuditRule, rule2 FileAuditRule, ignoreFlags bool) bool {
	if rule1.Path != rule2.Path {
		return false
	}
	if rule1.Permissions != rule2.Permissions {
		return false
	}
	if !ignoreFlags {
		return isEqual(rule1.Keys, rule2.Keys)
	}
	return true
}

func isEqual(slice1 []string, slice2 []string) bool {
	{
		if len(slice1) != len(slice1) {
			return false
		}
		for _, key := range slice1 {
			found := false
			for _, k := range slice2 {
				if key == k {
					found = true
					continue
				}
			}
			if !found {
				return false
			}
		}
	}
	return true
}

func isSyscallAuditRulesEqual(rule1 SyscallAuditRule, rule2 SyscallAuditRule, ignoreFlags bool) bool {
	if rule1.Action != rule2.Action {
		return false
	}
	if rule1.Filter != rule2.Filter {
		return false
	}
	if !isEqual(rule1.Syscalls, rule2.Syscalls) {
		return false
	}
	if len(rule1.Fields) == len(rule2.Fields) {
		var fieldSlice1 []string
		var fieldSlice2 []string
		for i := 0; i < len(rule1.Fields); i++ {
			fieldSlice1 = append(fieldSlice1, rule1.Fields[i].toString())
			fieldSlice2 = append(fieldSlice2, rule2.Fields[i].toString())
		}
		if !isEqual(fieldSlice1, fieldSlice2) {
			return false
		}
	} else {
		return false
	}
	if !ignoreFlags {
		return isEqual(rule1.Keys, rule2.Keys)
	}
	return true

}
