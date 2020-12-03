package libauditgo

// actionLookup is for mapping audit actions applied on auditRuleData
var actionLookup = map[uint32]string{
	AuditNever:    "never",
	AuditPossible: "possible",
	AuditAlways:   "always",
}

// flagLookup is for mapping flags applied on auditRuleData
var flagLookup = map[uint32]string{
	AuditFilterTask:    "task",
	AuditFilterEntry:   "entry",
	AuditFilterExit:    "exit",
	AuditFilterUser:    "user",
	AuditFilterExclude: "exclude",
}

// opLookup is for mapping operators applied on auditRuleData
var opLookup = map[uint32]string{
	AuditEqual:              "=",
	AuditNotEqual:           "!=",
	AuditGreaterThan:        ">",
	AuditGreaterThanOrEqual: ">=",
	AuditLessThan:           "<",
	AuditLessThanOrEqual:    "<=",
	AuditBitMaks:            "&",
	AuditBitTest:            "&=",
}

// fieldLookup is for mapping fields applied on auditRuleData and also used for
// interpreting fields set in auditRuleData struct
var fieldLookup = map[int]string{
	AuditPID:          "pid",
	AuditUID:          "uid",
	AuditEUID:         "euid",
	AuditSUID:         "suid",
	AuditFSUID:        "fsuid",
	AuditGID:          "gid",
	AuditEGID:         "egid",
	AuditSGID:         "sgid",
	AuditFSGID:        "fsgid",
	AuditLOGINUID:     "auid",
	AuditPers:         "pers",
	AuditArch:         "arch",
	AuditMsgType:      "msgtype",
	AuditSubjUser:     "Subjuser",
	AuditSubjRole:     "Subjrole",
	AuditSubjType:     "Subjtype",
	AuditSubjSen:      "Subjsen",
	AuditSubjClr:      "Subjclr",
	AuditPPID:         "ppid",
	AuditObjUser:      "obj_user",
	AuditObjRole:      "obj_role",
	AuditObjType:      "obj_type",
	AuditObjLevLow:    "obj_lev_low",
	AuditObjLevHigh:   "obj_lev_high",
	AuditDevMajor:     "devmajor",
	AuditDevMinor:     "devminor",
	AuditInode:        "inode",
	AuditExit:         "exit",
	AuditSuccess:      "success",
	AuditWatch:        "path",
	AuditPerm:         "perm",
	AuditDir:          "dir",
	AuditFileType:     "filetype",
	AuditObjUID:       "obj_uid",
	AuditObjGID:       "obj_gid",
	AuditFieldCompare: "field_compare",
	AuditArg0:         "a0",
	AuditArg1:         "a1",
	AuditArg2:         "a2",
	AuditArg3:         "a3",
	AuditFilterKey:    "key",
	AuditExe:          "exe",
}
