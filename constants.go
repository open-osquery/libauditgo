package libauditgo

import "fmt"

const (
	//AuditMaxFields is maximum number of fields in a rule
	AuditMaxFields = 64
	// AuditMaxKeyLenght is maximum length of audit key field
	AuditMaxKeyLenght = 256
	// AuditBitmaskSize is maximun size of bitmask
	AuditBitmaskSize = 64
	// PathMax is maximum length of dir/path field value
	PathMax = 4096
	// AuditSyscall Syscall event
	AuditSyscall uint16 = 1300 /* Syscall event */
)

// Permissions
const (
	AuditPermExecValue  = 1
	AuditPermWriteValue = 2
	AuditPermReadValue  = 4
	AuditPermAttrValue  = 8
)

// Rule Flags
// refrence : https://github.com/linux-audit/audit-kernel/blob/1860e379875dfe7271c649058aeddffe5afd9d0d/include/uapi/linux/audit.h#L147
const (
	AuditFilterUser    uint32 = 0 /* Apply rule to user-generated messages */
	AuditFilterTask    uint32 = 1 /* Apply rule at task creation (not syscall) */
	AuditFilterEntry   uint32 = 2 /* Apply rule at syscall entry */
	AuditFilterWatch   uint32 = 3 /* Apply rule to file system watches */
	AuditFilterExit    uint32 = 4 /* Apply rule at syscall exit */
	AuditFilterExclude uint32 = 5 /* Apply rule at Auditlog_start, corresponds to AUDIT_FILTER_EXCLUDE */
	/* These are used in filter control */
	AuditFilterMask  uint32 = 7   /* Mask to get actual filter */
	AuditFilterUnset uint32 = 128 /* This value means filter is unset */
)

// Rule Actions
// reference: https://github.com/linux-audit/audit-kernel/blob/1860e379875dfe7271c649058aeddffe5afd9d0d/include/uapi/linux/audit.h#L159
const (
	AuditNever    uint32 = 0 /* Do not build context if rule matches */
	AuditPossible uint32 = 1 /* Build context if rule matches  */
	AuditAlways   uint32 = 2 /* Generate audit record if rule matches */
)

// Operators
/* These are the supported operators.
 *	4  2  1  8
 *	=  >  <  ?
 *	----------
 *	0  0  0	 0	00	nonsense
 *	0  0  0	 1	08	&  bit mask
 *	0  0  1	 0	10	<
 *	0  1  0	 0	20	>
 *	0  1  1	 0	30	!=
 *	1  0  0	 0	40	=
 *	1  0  0	 1	48	&=  bit test
 *	1  0  1	 0	50	<=
 *	1  1  0	 0	60	>=
 *	1  1  1	 1	78	all operators
 */
// reference: https://github.com/linux-audit/audit-kernel/blob/1860e379875dfe7271c649058aeddffe5afd9d0d/include/uapi/linux/audit.h#L294
const (
	AuditBitMaks            = 0x08000000
	AuditLessThan           = 0x10000000
	AuditGreaterThan        = 0x20000000
	AuditNotEqual           = 0x30000000
	AuditEqual              = 0x40000000
	AuditBitTest            = (AuditBitMaks | AuditEqual)
	AuditLessThanOrEqual    = (AuditLessThan | AuditEqual)
	AuditGreaterThanOrEqual = (AuditGreaterThan | AuditEqual)
	AuditOperators          = (AuditEqual | AuditNotEqual | AuditBitMaks)
)

// Fields
const (
	AuditPID         = 0
	AuditUID         = 1
	AuditEUID        = 2
	AuditSUID        = 3
	AuditFSUID       = 4
	AuditGID         = 5
	AuditEGID        = 6
	AuditSGID        = 7
	AuditFSGID       = 8
	AuditLOGINUID    = 9
	AuditPers        = 10
	AuditArch        = 11
	AuditMsgType     = 12
	AuditSubjUser    = 13 /* security label user */
	AuditSubjRole    = 14 /* security label role */
	AuditSubjType    = 15 /* security label type */
	AuditSubjSen     = 16 /* security label sensitivity label */
	AuditSubjClr     = 17 /* security label clearance label */
	AuditPPID        = 18
	AuditObjUser     = 19
	AuditObjRole     = 20
	AuditObjType     = 21
	AuditObjLevLow   = 22
	AuditObjLevHigh  = 23
	AuditLoginUidSet = 24

	AuditDevMajor     = 100
	AuditDevMinor     = 101
	AuditInode        = 102
	AuditExit         = 103
	AuditSuccess      = 104
	AuditWatch        = 105
	AuditPerm         = 106
	AuditDir          = 107
	AuditFileType     = 108
	AuditObjUID       = 109
	AuditObjGID       = 110
	AuditFieldCompare = 111
	AuditExe          = 112

	AuditArg0      = 200
	AuditArg1      = (AuditArg0 + 1)
	AuditArg2      = (AuditArg0 + 2)
	AuditArg3      = (AuditArg0 + 3)
	AuditFilterKey = 210

	//--------------------------------

	// AuditFILTER_EXCLUDE = 0x05
	// PATH_MAX            = 4096
	// AuditMAX_KEY_LEN = 256
	//--------------------------------

	// AuditFIELD_COMPARE = 111
	// AuditEXE           = 112
	// AuditPERM_EXEC     = 1
	// AuditPERM_WRITE    = 2
	// AuditPERM_READ     = 4
	// AuditPERM_ATTR     = 8
)

const (
	/* distinguish syscall tables */
	__AuditARCH_64BIT  = 0x80000000
	__AuditARCH_LE     = 0x40000000
	AuditARCH_ALPHA    = (EM_ALPHA | __AuditARCH_64BIT | __AuditARCH_LE)
	AuditARCH_ARM      = (EM_ARM | __AuditARCH_LE)
	AuditARCH_ARMEB    = (EM_ARM)
	AuditARCH_CRIS     = (EM_CRIS | __AuditARCH_LE)
	AuditARCH_FRV      = (EM_FRV)
	AuditARCH_I386     = (EM_386 | __AuditARCH_LE)
	AuditARCH_IA64     = (EM_IA_64 | __AuditARCH_64BIT | __AuditARCH_LE)
	AuditARCH_M32R     = (EM_M32R)
	AuditARCH_M68K     = (EM_68K)
	AuditARCH_MIPS     = (EM_MIPS)
	AuditARCH_MIPSEL   = (EM_MIPS | __AuditARCH_LE)
	AuditARCH_MIPS64   = (EM_MIPS | __AuditARCH_64BIT)
	AuditARCH_MIPSEL64 = (EM_MIPS | __AuditARCH_64BIT | __AuditARCH_LE)
	//	AuditARCH_OPENRISC = (EM_OPENRISC)
	//	AuditARCH_PARISC   = (EM_PARISC)
	//	AuditARCH_PARISC64 = (EM_PARISC | __AuditARCH_64BIT)
	AuditARCH_PPC     = (EM_PPC)
	AuditARCH_PPC64   = (EM_PPC64 | __AuditARCH_64BIT)
	AuditARCH_S390    = (EM_S390)
	AuditARCH_S390X   = (EM_S390 | __AuditARCH_64BIT)
	AuditARCH_SH      = (EM_SH)
	AuditARCH_SHEL    = (EM_SH | __AuditARCH_LE)
	AuditARCH_SH64    = (EM_SH | __AuditARCH_64BIT)
	AuditARCH_SHEL64  = (EM_SH | __AuditARCH_64BIT | __AuditARCH_LE)
	AuditARCH_SPARC   = (EM_SPARC)
	AuditARCH_SPARC64 = (EM_SPARCV9 | __AuditARCH_64BIT)
	AuditARCH_X86_64  = (EM_X86_64 | __AuditARCH_64BIT | __AuditARCH_LE)
	///Temporary Solution need to add linux/elf-em.h
	EM_NONE  = 0
	EM_M32   = 1
	EM_SPARC = 2
	EM_386   = 3
	EM_68K   = 4
	EM_88K   = 5
	EM_486   = 6 /* Perhaps disused */
	EM_860   = 7
	EM_MIPS  = 8 /* MIPS R3000 (officially, big-endian only) */
	/* Next two are historical and binaries and
	   modules of these types will be rejected by
	   Linux.  */
	EM_MIPS_RS3_LE = 10 /* MIPS R3000 little-endian */
	EM_MIPS_RS4_BE = 10 /* MIPS R4000 big-endian */

	EM_PARISC      = 15     /* HPPA */
	EM_SPARC32PLUS = 18     /* Sun's "v8plus" */
	EM_PPC         = 20     /* PowerPC */
	EM_PPC64       = 21     /* PowerPC64 */
	EM_SPU         = 23     /* Cell BE SPU */
	EM_ARM         = 40     /* ARM 32 bit */
	EM_SH          = 42     /* SuperH */
	EM_SPARCV9     = 43     /* SPARC v9 64-bit */
	EM_IA_64       = 50     /* HP/Intel IA-64 */
	EM_X86_64      = 62     /* AMD x86-64 */
	EM_S390        = 22     /* IBM S/390 */
	EM_CRIS        = 76     /* Axis Communications 32-bit embedded processor */
	EM_V850        = 87     /* NEC v850 */
	EM_M32R        = 88     /* Renesas M32R */
	EM_MN10300     = 89     /* Panasonic/MEI MN10300, AM33 */
	EM_BLACKFIN    = 106    /* ADI Blackfin Processor */
	EM_TI_C6000    = 140    /* TI C6X DSPs */
	EM_AARCH64     = 183    /* ARM 64 bit */
	EM_FRV         = 0x5441 /* Fujitsu FR-V */
	EM_AVR32       = 0x18ad /* Atmel AVR32 */

	/*
	 * This is an interim value that we will use until the committee comes
	 * up with a final number.
	 */
	EM_ALPHA = 0x9026

	/* Bogus old v850 magic number, used by old tools. */
	EM_CYGNUS_V850 = 0x9080
	/* Bogus old m32r magic number, used by old tools. */
	EM_CYGNUS_M32R = 0x9041
	/* This is the old interim value for S/390 architecture */
	EM_S390_OLD = 0xA390
	/* Also Panasonic/MEI MN10300, AM33 */
	EM_CYGNUS_MN10300 = 0xbeef
	//AuditARCH determination purpose
	_UTSNAME_LENGTH          = 65
	_UTSNAME_DOMAIN_LENGTH   = _UTSNAME_LENGTH
	_UTSNAME_NODENAME_LENGTH = _UTSNAME_DOMAIN_LENGTH
)

type auditConstant uint16

const (
	AUDIT_GET         auditConstant = 1000 /* Get status */
	AUDIT_SET         auditConstant = 1001 /* Set status (enable/disable/auditd) */
	AUDIT_LIST        auditConstant = 1002 /* List syscall rules -- deprecated */
	AUDIT_ADD         auditConstant = 1003 /* Add syscall rule -- deprecated */
	AUDIT_DEL         auditConstant = 1004 /* Delete syscall rule -- deprecated */
	AUDIT_USER        auditConstant = 1005 /* Message from userspace -- deprecated */
	AUDIT_LOGIN       auditConstant = 1006 /* Define the login id and information */
	AUDIT_WATCH_INS   auditConstant = 1007 /* Insert file/dir watch entry */
	AUDIT_WATCH_REM   auditConstant = 1008 /* Remove file/dir watch entry */
	AUDIT_WATCH_LIST  auditConstant = 1009 /* List all file/dir watches */
	AUDIT_SIGNAL_INFO auditConstant = 1010 /* Get info about sender of signal to auditd */
	AUDIT_ADD_RULE    auditConstant = 1011 /* Add syscall filtering rule */
	AUDIT_DEL_RULE    auditConstant = 1012 /* Delete syscall filtering rule */
	AUDIT_LIST_RULES  auditConstant = 1013 /* List syscall filtering rules */
	AUDIT_TRIM        auditConstant = 1014 /* Trim junk from watched tree */
	AUDIT_MAKE_EQUIV  auditConstant = 1015 /* Append to watched tree */
	AUDIT_TTY_GET     auditConstant = 1016 /* Get TTY auditing status */
	AUDIT_TTY_SET     auditConstant = 1017 /* Set TTY auditing status */
	AUDIT_SET_FEATURE auditConstant = 1018 /* Turn an audit feature on or off */
	AUDIT_GET_FEATURE auditConstant = 1019 /* Get which features are enabled */

	AUDIT_FIRST_USER_MSG   auditConstant = 1100 /* First user space message */
	AUDIT_LAST_USER_MSG    auditConstant = 1199 /* Last user space message */
	AUDIT_USER_AUTH        auditConstant = 1100 /* User space authentication */
	AUDIT_USER_ACCT        auditConstant = 1101 /* User space acct change */
	AUDIT_USER_MGMT        auditConstant = 1102 /* User space acct management */
	AUDIT_CRED_ACQ         auditConstant = 1103 /* User space credential acquired */
	AUDIT_CRED_DISP        auditConstant = 1104 /* User space credential disposed */
	AUDIT_USER_START       auditConstant = 1105 /* User space session start */
	AUDIT_USER_END         auditConstant = 1106 /* User space session end */
	AUDIT_USER_AVC         auditConstant = 1107 /* User space avc message */
	AUDIT_USER_CHAUTHTOK   auditConstant = 1108 /* User space acct attr changed */
	AUDIT_USER_ERR         auditConstant = 1109 /* User space acct state err */
	AUDIT_CRED_REFR        auditConstant = 1110 /* User space credential refreshed */
	AUDIT_USYS_CONFIG      auditConstant = 1111 /* User space system config change */
	AUDIT_USER_LOGIN       auditConstant = 1112 /* User space user has logged in */
	AUDIT_USER_LOGOUT      auditConstant = 1113 /* User space user has logged out */
	AUDIT_ADD_USER         auditConstant = 1114 /* User space user account added */
	AUDIT_DEL_USER         auditConstant = 1115 /* User space user account deleted */
	AUDIT_ADD_GROUP        auditConstant = 1116 /* User space group added */
	AUDIT_DEL_GROUP        auditConstant = 1117 /* User space group deleted */
	AUDIT_DAC_CHECK        auditConstant = 1118 /* User space DAC check results */
	AUDIT_CHGRP_ID         auditConstant = 1119 /* User space group ID changed */
	AUDIT_TEST             auditConstant = 1120 /* Used for test success messages */
	AUDIT_TRUSTED_APP      auditConstant = 1121 /* Trusted app msg - freestyle text */
	AUDIT_USER_SELINUX_ERR auditConstant = 1122 /* SE Linux user space error */
	AUDIT_USER_CMD         auditConstant = 1123 /* User shell command and args */
	AUDIT_USER_TTY         auditConstant = 1124 /* Non-ICANON TTY input meaning */
	AUDIT_CHUSER_ID        auditConstant = 1125 /* Changed user ID supplemental data */
	AUDIT_GRP_AUTH         auditConstant = 1126 /* Authentication for group password */
	AUDIT_SYSTEM_BOOT      auditConstant = 1127 /* System boot */
	AUDIT_SYSTEM_SHUTDOWN  auditConstant = 1128 /* System shutdown */
	AUDIT_SYSTEM_RUNLEVEL  auditConstant = 1129 /* System runlevel change */
	AUDIT_SERVICE_START    auditConstant = 1130 /* Service (daemon) start */
	AUDIT_SERVICE_STOP     auditConstant = 1131 /* Service (daemon) stop */
	AUDIT_GRP_MGMT         auditConstant = 1132 /* Group account attr was modified */
	AUDIT_GRP_CHAUTHTOK    auditConstant = 1133 /* Group acct password or pin changed */
	AUDIT_MAC_CHECK        auditConstant = 1134 /* User space MAC decision results */
	AUDIT_ACCT_LOCK        auditConstant = 1135 /* User's account locked by admin */
	AUDIT_ACCT_UNLOCK      auditConstant = 1136 /* User's account unlocked by admin */

	AUDIT_FIRST_DAEMON    auditConstant = 1200
	AUDIT_LAST_DAEMON     auditConstant = 1299
	AUDIT_DAEMON_CONFIG   auditConstant = 1203 /* Daemon config change */
	AUDIT_DAEMON_RECONFIG auditConstant = 1204 /* Auditd should reconfigure */
	AUDIT_DAEMON_ROTATE   auditConstant = 1205 /* Auditd should rotate logs */
	AUDIT_DAEMON_RESUME   auditConstant = 1206 /* Auditd should resume logging */
	AUDIT_DAEMON_ACCEPT   auditConstant = 1207 /* Auditd accepted remote connection */
	AUDIT_DAEMON_CLOSE    auditConstant = 1208 /* Auditd closed remote connection */

	AUDIT_SYSCALL auditConstant = 1300 /* Syscall event */
	/* AUDIT_FS_WATCH     auditConstant       =   1301     * Deprecated */
	AUDIT_PATH           auditConstant = 1302 /* Filename path information */
	AUDIT_IPC            auditConstant = 1303 /* IPC record */
	AUDIT_SOCKETCALL     auditConstant = 1304 /* sys_socketcall arguments */
	AUDIT_CONFIG_CHANGE  auditConstant = 1305 /* Audit system configuration change */
	AUDIT_SOCKADDR       auditConstant = 1306 /* sockaddr copied as syscall arg */
	AUDIT_CWD            auditConstant = 1307 /* Current working directory */
	AUDIT_EXECVE         auditConstant = 1309 /* execve arguments */
	AUDIT_IPC_SET_PERM   auditConstant = 1311 /* IPC new permissions record type */
	AUDIT_MQ_OPEN        auditConstant = 1312 /* POSIX MQ open record type */
	AUDIT_MQ_SENDRECV    auditConstant = 1313 /* POSIX MQ send/receive record type */
	AUDIT_MQ_NOTIFY      auditConstant = 1314 /* POSIX MQ notify record type */
	AUDIT_MQ_GETSETATTR  auditConstant = 1315 /* POSIX MQ get/set attribute record type */
	AUDIT_KERNEL_OTHER   auditConstant = 1316 /* For use by 3rd party modules */
	AUDIT_FD_PAIR        auditConstant = 1317 /* audit record for pipe/socketpair */
	AUDIT_OBJ_PID        auditConstant = 1318 /* ptrace target */
	AUDIT_TTY            auditConstant = 1319 /* Input on an administrative TTY */
	AUDIT_EOE            auditConstant = 1320 /* End of multi-record event */
	AUDIT_BPRM_FCAPS     auditConstant = 1321 /* Information about fcaps increasing perms */
	AUDIT_CAPSET         auditConstant = 1322 /* Record showing argument to sys_capset */
	AUDIT_MMAP           auditConstant = 1323 /* Record showing descriptor and flags in mmap */
	AUDIT_NETFILTER_PKT  auditConstant = 1324 /* Packets traversing netfilter chains */
	AUDIT_NETFILTER_CFG  auditConstant = 1325 /* Netfilter chain modifications */
	AUDIT_SECCOMP        auditConstant = 1326 /* Secure Computing event */
	AUDIT_PROCTITLE      auditConstant = 1327 /* Proctitle emit event */
	AUDIT_FEATURE_CHANGE auditConstant = 1328 /* audit log listing feature changes */

	/* AUDIT_FIRST_EVENT       1300 */ //TODO: libaudit define this as AUDIT_FIRST_EVENT but audit.h differently.
	AUDIT_LAST_EVENT                   auditConstant = 1399

	/* AUDIT_FIRST_SELINUX     1400 */ // TODO: libaudit define this as AUDIT_FIRST_SELINUX but audit.h as AUDIT_AVC
	AUDIT_AVC                          auditConstant = 1400 /* SE Linux avc denial or grant */
	AUDIT_SELINUX_ERR                  auditConstant = 1401 /* internal SE Linux Errors */
	AUDIT_AVC_PATH                     auditConstant = 1402 /* dentry, vfsmount pair from avc */
	AUDIT_MAC_POLICY_LOAD              auditConstant = 1403 /* Policy file load */
	AUDIT_MAC_STATUS                   auditConstant = 1404 /* Changed enforcing,permissive,off */
	AUDIT_MAC_CONFIG_CHANGE            auditConstant = 1405 /* Changes to booleans */
	AUDIT_MAC_UNLBL_ALLOW              auditConstant = 1406 /* NetLabel: allow unlabeled traffic */
	AUDIT_MAC_CIPSOV4_ADD              auditConstant = 1407 /* NetLabel: add CIPSOv4 DOI entry */
	AUDIT_MAC_CIPSOV4_DEL              auditConstant = 1408 /* NetLabel: del CIPSOv4 DOI entry */
	AUDIT_MAC_MAP_ADD                  auditConstant = 1409 /* NetLabel: add LSM domain mapping */
	AUDIT_MAC_MAP_DEL                  auditConstant = 1410 /* NetLabel: del LSM domain mapping */
	AUDIT_MAC_IPSEC_ADDSA              auditConstant = 1411 /* Not used */
	AUDIT_MAC_IPSEC_DELSA              auditConstant = 1412 /* Not used  */
	AUDIT_MAC_IPSEC_ADDSPD             auditConstant = 1413 /* Not used */
	AUDIT_MAC_IPSEC_DELSPD             auditConstant = 1414 /* Not used */
	AUDIT_MAC_IPSEC_EVENT              auditConstant = 1415 /* Audit an IPSec event */
	AUDIT_MAC_UNLBL_STCADD             auditConstant = 1416 /* NetLabel: add a static label */
	AUDIT_MAC_UNLBL_STCDEL             auditConstant = 1417 /* NetLabel: del a static label */
	AUDIT_LAST_SELINUX                 auditConstant = 1499

	AUDIT_FIRST_APPARMOR auditConstant = 1500
	AUDIT_LAST_APPARMOR  auditConstant = 1599

	AUDIT_AA               auditConstant = 1500 /* Not upstream yet*/
	AUDIT_APPARMOR_AUDIT   auditConstant = 1501
	AUDIT_APPARMOR_ALLOWED auditConstant = 1502
	AUDIT_APPARMOR_DENIED  auditConstant = 1503
	AUDIT_APPARMOR_HT      auditConstant = 1504
	AUDIT_APPARMOR_STATUS  auditConstant = 1505
	AUDIT_APPARMOR_ERROR   auditConstant = 1506

	AUDIT_FIRST_KERN_CRYPTO_MSG auditConstant = 1600
	AUDIT_LAST_KERN_CRYPTO_MSG  auditConstant = 1699

	// AUDIT_FIRST_KERN_ANOM_MSG auditConstant = 1700
	AUDIT_LAST_KERN_ANOM_MSG auditConstant = 1799
	AUDIT_ANOM_PROMISCUOUS   auditConstant = 1700 /* Device changed promiscuous mode */
	AUDIT_ANOM_ABEND         auditConstant = 1701 /* Process ended abnormally */
	AUDIT_ANOM_LINK          auditConstant = 1702 /* Suspicious use of file links */

	AUDIT_INTEGRITY_FIRST_MSG auditConstant = 1800
	AUDIT_TINTEGRITY_LAST_MSG auditConstant = 1899

	AUDIT_INTEGRITY_DATA     auditConstant = 1800 /* Data integrity verification */
	AUDIT_INTEGRITY_METADATA auditConstant = 1801 // Metadata integrity verification
	AUDIT_INTEGRITY_STATUS   auditConstant = 1802 /* integrity enable status */
	AUDIT_INTEGRITY_HASH     auditConstant = 1803 /* integrity HASH type */
	AUDIT_INTEGRITY_PCR      auditConstant = 1804 /* PCR invalidation msgs */
	AUDIT_INTEGRITY_RULE     auditConstant = 1805 /* Policy rule */
	AUDIT_KERNEL             auditConstant = 2000 /* Asynchronous audit record. NOT A REQUEST. */

	AUDIT_FIRST_ANOM_MSG           auditConstant = 2100
	AUDIT_LAST_ANOM_MSG            auditConstant = 2199
	AUDIT_ANOM_LOGIN_FAILURES      auditConstant = 2100 // Failed login limit reached
	AUDIT_ANOM_LOGIN_TIME          auditConstant = 2101 // Login attempted at bad time
	AUDIT_ANOM_LOGIN_SESSIONS      auditConstant = 2102 // Max concurrent sessions reached
	AUDIT_ANOM_LOGIN_ACCT          auditConstant = 2103 // Login attempted to watched acct
	AUDIT_ANOM_LOGIN_LOCATION      auditConstant = 2104 // Login from forbidden location
	AUDIT_ANOM_MAX_DAC             auditConstant = 2105 // Max DAC failures reached
	AUDIT_ANOM_MAX_MAC             auditConstant = 2106 // Max MAC failures reached
	AUDIT_ANOM_AMTU_FAIL           auditConstant = 2107 // AMTU failure
	AUDIT_ANOM_RBAC_FAIL           auditConstant = 2108 // RBAC self test failure
	AUDIT_ANOM_RBAC_INTEGRITY_FAIL auditConstant = 2109 // RBAC file Tegrity failure
	AUDIT_ANOM_CRYPTO_FAIL         auditConstant = 2110 // Crypto system test failure
	AUDIT_ANOM_ACCESS_FS           auditConstant = 2111 // Access of file or dir
	AUDIT_ANOM_EXEC                auditConstant = 2112 // Execution of file
	AUDIT_ANOM_MK_EXEC             auditConstant = 2113 // Make an executable
	AUDIT_ANOM_ADD_ACCT            auditConstant = 2114 // Adding an acct
	AUDIT_ANOM_DEL_ACCT            auditConstant = 2115 // Deleting an acct
	AUDIT_ANOM_MOD_ACCT            auditConstant = 2116 // Changing an acct
	AUDIT_ANOM_ROOT_TRANS          auditConstant = 2117 // User became root

	AUDIT_FIRST_ANOM_RESP        auditConstant = 2200
	AUDIT_LAST_ANOM_RESP         auditConstant = 2299
	AUDIT_RESP_ANOMALY           auditConstant = 2200 /* Anomaly not reacted to */
	AUDIT_RESP_ALERT             auditConstant = 2201 /* Alert email was sent */
	AUDIT_RESP_KILL_PROC         auditConstant = 2202 /* Kill program */
	AUDIT_RESP_TERM_ACCESS       auditConstant = 2203 /* Terminate session */
	AUDIT_RESP_ACCT_REMOTE       auditConstant = 2204 /* Acct locked from remote access*/
	AUDIT_RESP_ACCT_LOCK_TIMED   auditConstant = 2205 /* User acct locked for time */
	AUDIT_RESP_ACCT_UNLOCK_TIMED auditConstant = 2206 /* User acct unlocked from time */
	AUDIT_RESP_ACCT_LOCK         auditConstant = 2207 /* User acct was locked */
	AUDIT_RESP_TERM_LOCK         auditConstant = 2208 /* Terminal was locked */
	AUDIT_RESP_SEBOOL            auditConstant = 2209 /* Set an SE Linux boolean */
	AUDIT_RESP_EXEC              auditConstant = 2210 /* Execute a script */
	AUDIT_RESP_SINGLE            auditConstant = 2211 /* Go to single user mode */
	AUDIT_RESP_HALT              auditConstant = 2212 /* take the system down */

	AUDIT_FIRST_USER_LSPP_MSG    auditConstant = 2300
	AUDIT_LAST_USER_LSPP_MSG     auditConstant = 2399
	AUDIT_USER_ROLE_CHANGE       auditConstant = 2300 /* User changed to a new role */
	AUDIT_ROLE_ASSIGN            auditConstant = 2301 /* Admin assigned user to role */
	AUDIT_ROLE_REMOVE            auditConstant = 2302 /* Admin removed user from role */
	AUDIT_LABEL_OVERRIDE         auditConstant = 2303 /* Admin is overriding a label */
	AUDIT_LABEL_LEVEL_CHANGE     auditConstant = 2304 /* Object's level was changed */
	AUDIT_USER_LABELED_EXPORT    auditConstant = 2305 /* Object exported with label */
	AUDIT_USER_UNLABELED_EXPORT  auditConstant = 2306 /* Object exported without label */
	AUDIT_DEV_ALLOC              auditConstant = 2307 /* Device was allocated */
	AUDIT_DEV_DEALLOC            auditConstant = 2308 /* Device was deallocated */
	AUDIT_FS_RELABEL             auditConstant = 2309 /* Filesystem relabeled */
	AUDIT_USER_MAC_POLICY_LOAD   auditConstant = 2310 /* Userspc daemon loaded policy */
	AUDIT_ROLE_MODIFY            auditConstant = 2311 /* Admin modified a role */
	AUDIT_USER_MAC_CONFIG_CHANGE auditConstant = 2312 /* Change made to MAC policy */

	AUDIT_FIRST_CRYPTO_MSG         auditConstant = 2400
	AUDIT_CRYPTO_TEST_USER         auditConstant = 2400 /* Crypto test results */
	AUDIT_CRYPTO_PARAM_CHANGE_USER auditConstant = 2401 /* Crypto attribute change */
	AUDIT_CRYPTO_LOGIN             auditConstant = 2402 /* Logged in as crypto officer */
	AUDIT_CRYPTO_LOGOUT            auditConstant = 2403 /* Logged out from crypto */
	AUDIT_CRYPTO_KEY_USER          auditConstant = 2404 /* Create,delete,negotiate */
	AUDIT_CRYPTO_FAILURE_USER      auditConstant = 2405 /* Fail decrypt,encrypt,randomiz */
	AUDIT_CRYPTO_REPLAY_USER       auditConstant = 2406 /* Crypto replay detected */
	AUDIT_CRYPTO_SESSION           auditConstant = 2407 /* Record parameters set during TLS session establishment */
	AUDIT_CRYPTO_IKE_SA            auditConstant = 2408 /* Record parameters related to IKE SA */
	AUDIT_CRYPTO_IPSEC_SA          auditConstant = 2409 /* Record parameters related to IPSEC SA */

	AUDIT_LAST_CRYPTO_MSG auditConstant = 2499

	AUDIT_FIRST_VIRT_MSG  auditConstant = 2500
	AUDIT_VIRT_CONTROL    auditConstant = 2500 /* Start, Pause, Stop VM */
	AUDIT_VIRT_RESOURCE   auditConstant = 2501 /* Resource assignment */
	AUDIT_VIRT_MACHINE_ID auditConstant = 2502 /* Binding of label to VM */
	AUDIT_LAST_VIRT_MSG   auditConstant = 2599
	AUDIT_LAST_USER_MSG2  auditConstant = 2999
	// Field Comparing Constants
	AUDIT_COMPARE_UID_TO_OBJ_UID   auditConstant = 1
	AUDIT_COMPARE_GID_TO_OBJ_GID   auditConstant = 2
	AUDIT_COMPARE_EUID_TO_OBJ_UID  auditConstant = 3
	AUDIT_COMPARE_EGID_TO_OBJ_GID  auditConstant = 4
	AUDIT_COMPARE_AUID_TO_OBJ_UID  auditConstant = 5
	AUDIT_COMPARE_SUID_TO_OBJ_UID  auditConstant = 6
	AUDIT_COMPARE_SGID_TO_OBJ_GID  auditConstant = 7
	AUDIT_COMPARE_FSUID_TO_OBJ_UID auditConstant = 8
	AUDIT_COMPARE_FSGID_TO_OBJ_GID auditConstant = 9
	AUDIT_COMPARE_UID_TO_AUID      auditConstant = 10
	AUDIT_COMPARE_UID_TO_EUID      auditConstant = 11
	AUDIT_COMPARE_UID_TO_FSUID     auditConstant = 12
	AUDIT_COMPARE_UID_TO_SUID      auditConstant = 13
	AUDIT_COMPARE_AUID_TO_FSUID    auditConstant = 14
	AUDIT_COMPARE_AUID_TO_SUID     auditConstant = 15
	AUDIT_COMPARE_AUID_TO_EUID     auditConstant = 16
	AUDIT_COMPARE_EUID_TO_SUID     auditConstant = 17
	AUDIT_COMPARE_EUID_TO_FSUID    auditConstant = 18
	AUDIT_COMPARE_SUID_TO_FSUID    auditConstant = 19
	AUDIT_COMPARE_GID_TO_EGID      auditConstant = 20
	AUDIT_COMPARE_GID_TO_FSGID     auditConstant = 21
	AUDIT_COMPARE_GID_TO_SGID      auditConstant = 22
	AUDIT_COMPARE_EGID_TO_FSGID    auditConstant = 23
	AUDIT_COMPARE_EGID_TO_SGID     auditConstant = 24
	AUDIT_COMPARE_SGID_TO_FSGID    auditConstant = 25
)
const _auditConstant_name = "AUDIT_COMPARE_UID_TO_OBJ_UIDAUDIT_COMPARE_GID_TO_OBJ_GIDAUDIT_COMPARE_EUID_TO_OBJ_UIDAUDIT_COMPARE_EGID_TO_OBJ_GIDAUDIT_COMPARE_AUID_TO_OBJ_UIDAUDIT_COMPARE_SUID_TO_OBJ_UIDAUDIT_COMPARE_SGID_TO_OBJ_GIDAUDIT_COMPARE_FSUID_TO_OBJ_UIDAUDIT_COMPARE_FSGID_TO_OBJ_GIDAUDIT_COMPARE_UID_TO_AUIDAUDIT_COMPARE_UID_TO_EUIDAUDIT_COMPARE_UID_TO_FSUIDAUDIT_COMPARE_UID_TO_SUIDAUDIT_COMPARE_AUID_TO_FSUIDAUDIT_COMPARE_AUID_TO_SUIDAUDIT_COMPARE_AUID_TO_EUIDAUDIT_COMPARE_EUID_TO_SUIDAUDIT_COMPARE_EUID_TO_FSUIDAUDIT_COMPARE_SUID_TO_FSUIDAUDIT_COMPARE_GID_TO_EGIDAUDIT_COMPARE_GID_TO_FSGIDAUDIT_COMPARE_GID_TO_SGIDAUDIT_COMPARE_EGID_TO_FSGIDAUDIT_COMPARE_EGID_TO_SGIDAUDIT_COMPARE_SGID_TO_FSGIDAUDIT_GETAUDIT_SETAUDIT_LISTAUDIT_ADDAUDIT_DELAUDIT_USERAUDIT_LOGINAUDIT_WATCH_INSAUDIT_WATCH_REMAUDIT_WATCH_LISTAUDIT_SIGNAL_INFOAUDIT_ADD_RULEAUDIT_DEL_RULEAUDIT_LIST_RULESAUDIT_TRIMAUDIT_MAKE_EQUIVAUDIT_TTY_GETAUDIT_TTY_SETAUDIT_SET_FEATUREAUDIT_GET_FEATUREAUDIT_FIRST_USER_MSGAUDIT_USER_ACCTAUDIT_USER_MGMTAUDIT_CRED_ACQAUDIT_CRED_DISPAUDIT_USER_STARTAUDIT_USER_ENDAUDIT_USER_AVCAUDIT_USER_CHAUTHTOKAUDIT_USER_ERRAUDIT_CRED_REFRAUDIT_USYS_CONFIGAUDIT_USER_LOGINAUDIT_USER_LOGOUTAUDIT_ADD_USERAUDIT_DEL_USERAUDIT_ADD_GROUPAUDIT_DEL_GROUPAUDIT_DAC_CHECKAUDIT_CHGRP_IDAUDIT_TESTAUDIT_TRUSTED_APPAUDIT_USER_SELINUX_ERRAUDIT_USER_CMDAUDIT_USER_TTYAUDIT_CHUSER_IDAUDIT_GRP_AUTHAUDIT_SYSTEM_BOOTAUDIT_SYSTEM_SHUTDOWNAUDIT_SYSTEM_RUNLEVELAUDIT_SERVICE_STARTAUDIT_SERVICE_STOPAUDIT_GRP_MGMTAUDIT_GRP_CHAUTHTOKAUDIT_MAC_CHECKAUDIT_ACCT_LOCKAUDIT_ACCT_UNLOCKAUDIT_LAST_USER_MSGAUDIT_FIRST_DAEMONAUDIT_DAEMON_CONFIGAUDIT_DAEMON_RECONFIGAUDIT_DAEMON_ROTATEAUDIT_DAEMON_RESUMEAUDIT_DAEMON_ACCEPTAUDIT_DAEMON_CLOSEAUDIT_LAST_DAEMONAUDIT_SYSCALLAUDIT_PATHAUDIT_IPCAUDIT_SOCKETCALLAUDIT_CONFIG_CHANGEAUDIT_SOCKADDRAUDIT_CWDAUDIT_EXECVEAUDIT_IPC_SET_PERMAUDIT_MQ_OPENAUDIT_MQ_SENDRECVAUDIT_MQ_NOTIFYAUDIT_MQ_GETSETATTRAUDIT_KERNEL_OTHERAUDIT_FD_PAIRAUDIT_OBJ_PIDAUDIT_TTYAUDIT_EOEAUDIT_BPRM_FCAPSAUDIT_CAPSETAUDIT_MMAPAUDIT_NETFILTER_PKTAUDIT_NETFILTER_CFGAUDIT_SECCOMPAUDIT_PROCTITLEAUDIT_FEATURE_CHANGEAUDIT_LAST_EVENTAUDIT_AVCAUDIT_SELINUX_ERRAUDIT_AVC_PATHAUDIT_MAC_POLICY_LOADAUDIT_MAC_STATUSAUDIT_MAC_CONFIG_CHANGEAUDIT_MAC_UNLBL_ALLOWAUDIT_MAC_CIPSOV4_ADDAUDIT_MAC_CIPSOV4_DELAUDIT_MAC_MAP_ADDAUDIT_MAC_MAP_DELAUDIT_MAC_IPSEC_ADDSAAUDIT_MAC_IPSEC_DELSAAUDIT_MAC_IPSEC_ADDSPDAUDIT_MAC_IPSEC_DELSPDAUDIT_MAC_IPSEC_EVENTAUDIT_MAC_UNLBL_STCADDAUDIT_MAC_UNLBL_STCDELAUDIT_LAST_SELINUXAUDIT_FIRST_APPARMORAUDIT_APPARMOR_AUDITAUDIT_APPARMOR_ALLOWEDAUDIT_APPARMOR_DENIEDAUDIT_APPARMOR_HTAUDIT_APPARMOR_STATUSAUDIT_APPARMOR_ERRORAUDIT_LAST_APPARMORAUDIT_FIRST_KERN_CRYPTO_MSGAUDIT_LAST_KERN_CRYPTO_MSGAUDIT_ANOM_PROMISCUOUSAUDIT_ANOM_ABENDAUDIT_ANOM_LINKAUDIT_LAST_KERN_ANOM_MSGAUDIT_INTEGRITY_FIRST_MSGAUDIT_INTEGRITY_METADATAAUDIT_INTEGRITY_STATUSAUDIT_INTEGRITY_HASHAUDIT_INTEGRITY_PCRAUDIT_INTEGRITY_RULEAUDIT_TINTEGRITY_LAST_MSGAUDIT_KERNELAUDIT_FIRST_ANOM_MSGAUDIT_ANOM_LOGIN_TIMEAUDIT_ANOM_LOGIN_SESSIONSAUDIT_ANOM_LOGIN_ACCTAUDIT_ANOM_LOGIN_LOCATIONAUDIT_ANOM_MAX_DACAUDIT_ANOM_MAX_MACAUDIT_ANOM_AMTU_FAILAUDIT_ANOM_RBAC_FAILAUDIT_ANOM_RBAC_INTEGRITY_FAILAUDIT_ANOM_CRYPTO_FAILAUDIT_ANOM_ACCESS_FSAUDIT_ANOM_EXECAUDIT_ANOM_MK_EXECAUDIT_ANOM_ADD_ACCTAUDIT_ANOM_DEL_ACCTAUDIT_ANOM_MOD_ACCTAUDIT_ANOM_ROOT_TRANSAUDIT_LAST_ANOM_MSGAUDIT_FIRST_ANOM_RESPAUDIT_RESP_ALERTAUDIT_RESP_KILL_PROCAUDIT_RESP_TERM_ACCESSAUDIT_RESP_ACCT_REMOTEAUDIT_RESP_ACCT_LOCK_TIMEDAUDIT_RESP_ACCT_UNLOCK_TIMEDAUDIT_RESP_ACCT_LOCKAUDIT_RESP_TERM_LOCKAUDIT_RESP_SEBOOLAUDIT_RESP_EXECAUDIT_RESP_SINGLEAUDIT_RESP_HALTAUDIT_LAST_ANOM_RESPAUDIT_FIRST_USER_LSPP_MSGAUDIT_ROLE_ASSIGNAUDIT_ROLE_REMOVEAUDIT_LABEL_OVERRIDEAUDIT_LABEL_LEVEL_CHANGEAUDIT_USER_LABELED_EXPORTAUDIT_USER_UNLABELED_EXPORTAUDIT_DEV_ALLOCAUDIT_DEV_DEALLOCAUDIT_FS_RELABELAUDIT_USER_MAC_POLICY_LOADAUDIT_ROLE_MODIFYAUDIT_USER_MAC_CONFIG_CHANGEAUDIT_LAST_USER_LSPP_MSGAUDIT_FIRST_CRYPTO_MSGAUDIT_CRYPTO_PARAM_CHANGE_USERAUDIT_CRYPTO_LOGINAUDIT_CRYPTO_LOGOUTAUDIT_CRYPTO_KEY_USERAUDIT_CRYPTO_FAILURE_USERAUDIT_CRYPTO_REPLAY_USERAUDIT_CRYPTO_SESSIONAUDIT_CRYPTO_IKE_SAAUDIT_CRYPTO_IPSEC_SAAUDIT_LAST_CRYPTO_MSGAUDIT_FIRST_VIRT_MSGAUDIT_VIRT_RESOURCEAUDIT_VIRT_MACHINE_IDAUDIT_LAST_VIRT_MSGAUDIT_LAST_USER_MSG2"

var _auditConstant_map = map[auditConstant]string{
	1:    _auditConstant_name[0:28],
	2:    _auditConstant_name[28:56],
	3:    _auditConstant_name[56:85],
	4:    _auditConstant_name[85:114],
	5:    _auditConstant_name[114:143],
	6:    _auditConstant_name[143:172],
	7:    _auditConstant_name[172:201],
	8:    _auditConstant_name[201:231],
	9:    _auditConstant_name[231:261],
	10:   _auditConstant_name[261:286],
	11:   _auditConstant_name[286:311],
	12:   _auditConstant_name[311:337],
	13:   _auditConstant_name[337:362],
	14:   _auditConstant_name[362:389],
	15:   _auditConstant_name[389:415],
	16:   _auditConstant_name[415:441],
	17:   _auditConstant_name[441:467],
	18:   _auditConstant_name[467:494],
	19:   _auditConstant_name[494:521],
	20:   _auditConstant_name[521:546],
	21:   _auditConstant_name[546:572],
	22:   _auditConstant_name[572:597],
	23:   _auditConstant_name[597:624],
	24:   _auditConstant_name[624:650],
	25:   _auditConstant_name[650:677],
	1000: _auditConstant_name[677:686],
	1001: _auditConstant_name[686:695],
	1002: _auditConstant_name[695:705],
	1003: _auditConstant_name[705:714],
	1004: _auditConstant_name[714:723],
	1005: _auditConstant_name[723:733],
	1006: _auditConstant_name[733:744],
	1007: _auditConstant_name[744:759],
	1008: _auditConstant_name[759:774],
	1009: _auditConstant_name[774:790],
	1010: _auditConstant_name[790:807],
	1011: _auditConstant_name[807:821],
	1012: _auditConstant_name[821:835],
	1013: _auditConstant_name[835:851],
	1014: _auditConstant_name[851:861],
	1015: _auditConstant_name[861:877],
	1016: _auditConstant_name[877:890],
	1017: _auditConstant_name[890:903],
	1018: _auditConstant_name[903:920],
	1019: _auditConstant_name[920:937],
	1100: _auditConstant_name[937:957],
	1101: _auditConstant_name[957:972],
	1102: _auditConstant_name[972:987],
	1103: _auditConstant_name[987:1001],
	1104: _auditConstant_name[1001:1016],
	1105: _auditConstant_name[1016:1032],
	1106: _auditConstant_name[1032:1046],
	1107: _auditConstant_name[1046:1060],
	1108: _auditConstant_name[1060:1080],
	1109: _auditConstant_name[1080:1094],
	1110: _auditConstant_name[1094:1109],
	1111: _auditConstant_name[1109:1126],
	1112: _auditConstant_name[1126:1142],
	1113: _auditConstant_name[1142:1159],
	1114: _auditConstant_name[1159:1173],
	1115: _auditConstant_name[1173:1187],
	1116: _auditConstant_name[1187:1202],
	1117: _auditConstant_name[1202:1217],
	1118: _auditConstant_name[1217:1232],
	1119: _auditConstant_name[1232:1246],
	1120: _auditConstant_name[1246:1256],
	1121: _auditConstant_name[1256:1273],
	1122: _auditConstant_name[1273:1295],
	1123: _auditConstant_name[1295:1309],
	1124: _auditConstant_name[1309:1323],
	1125: _auditConstant_name[1323:1338],
	1126: _auditConstant_name[1338:1352],
	1127: _auditConstant_name[1352:1369],
	1128: _auditConstant_name[1369:1390],
	1129: _auditConstant_name[1390:1411],
	1130: _auditConstant_name[1411:1430],
	1131: _auditConstant_name[1430:1448],
	1132: _auditConstant_name[1448:1462],
	1133: _auditConstant_name[1462:1481],
	1134: _auditConstant_name[1481:1496],
	1135: _auditConstant_name[1496:1511],
	1136: _auditConstant_name[1511:1528],
	1199: _auditConstant_name[1528:1547],
	1200: _auditConstant_name[1547:1565],
	1203: _auditConstant_name[1565:1584],
	1204: _auditConstant_name[1584:1605],
	1205: _auditConstant_name[1605:1624],
	1206: _auditConstant_name[1624:1643],
	1207: _auditConstant_name[1643:1662],
	1208: _auditConstant_name[1662:1680],
	1299: _auditConstant_name[1680:1697],
	1300: _auditConstant_name[1697:1710],
	1302: _auditConstant_name[1710:1720],
	1303: _auditConstant_name[1720:1729],
	1304: _auditConstant_name[1729:1745],
	1305: _auditConstant_name[1745:1764],
	1306: _auditConstant_name[1764:1778],
	1307: _auditConstant_name[1778:1787],
	1309: _auditConstant_name[1787:1799],
	1311: _auditConstant_name[1799:1817],
	1312: _auditConstant_name[1817:1830],
	1313: _auditConstant_name[1830:1847],
	1314: _auditConstant_name[1847:1862],
	1315: _auditConstant_name[1862:1881],
	1316: _auditConstant_name[1881:1899],
	1317: _auditConstant_name[1899:1912],
	1318: _auditConstant_name[1912:1925],
	1319: _auditConstant_name[1925:1934],
	1320: _auditConstant_name[1934:1943],
	1321: _auditConstant_name[1943:1959],
	1322: _auditConstant_name[1959:1971],
	1323: _auditConstant_name[1971:1981],
	1324: _auditConstant_name[1981:2000],
	1325: _auditConstant_name[2000:2019],
	1326: _auditConstant_name[2019:2032],
	1327: _auditConstant_name[2032:2047],
	1328: _auditConstant_name[2047:2067],
	1399: _auditConstant_name[2067:2083],
	1400: _auditConstant_name[2083:2092],
	1401: _auditConstant_name[2092:2109],
	1402: _auditConstant_name[2109:2123],
	1403: _auditConstant_name[2123:2144],
	1404: _auditConstant_name[2144:2160],
	1405: _auditConstant_name[2160:2183],
	1406: _auditConstant_name[2183:2204],
	1407: _auditConstant_name[2204:2225],
	1408: _auditConstant_name[2225:2246],
	1409: _auditConstant_name[2246:2263],
	1410: _auditConstant_name[2263:2280],
	1411: _auditConstant_name[2280:2301],
	1412: _auditConstant_name[2301:2322],
	1413: _auditConstant_name[2322:2344],
	1414: _auditConstant_name[2344:2366],
	1415: _auditConstant_name[2366:2387],
	1416: _auditConstant_name[2387:2409],
	1417: _auditConstant_name[2409:2431],
	1499: _auditConstant_name[2431:2449],
	1500: _auditConstant_name[2449:2469],
	1501: _auditConstant_name[2469:2489],
	1502: _auditConstant_name[2489:2511],
	1503: _auditConstant_name[2511:2532],
	1504: _auditConstant_name[2532:2549],
	1505: _auditConstant_name[2549:2570],
	1506: _auditConstant_name[2570:2590],
	1599: _auditConstant_name[2590:2609],
	1600: _auditConstant_name[2609:2636],
	1699: _auditConstant_name[2636:2662],
	1700: _auditConstant_name[2662:2684],
	1701: _auditConstant_name[2684:2700],
	1702: _auditConstant_name[2700:2715],
	1799: _auditConstant_name[2715:2739],
	1800: _auditConstant_name[2739:2764],
	1801: _auditConstant_name[2764:2788],
	1802: _auditConstant_name[2788:2810],
	1803: _auditConstant_name[2810:2830],
	1804: _auditConstant_name[2830:2849],
	1805: _auditConstant_name[2849:2869],
	1899: _auditConstant_name[2869:2894],
	2000: _auditConstant_name[2894:2906],
	2100: _auditConstant_name[2906:2926],
	2101: _auditConstant_name[2926:2947],
	2102: _auditConstant_name[2947:2972],
	2103: _auditConstant_name[2972:2993],
	2104: _auditConstant_name[2993:3018],
	2105: _auditConstant_name[3018:3036],
	2106: _auditConstant_name[3036:3054],
	2107: _auditConstant_name[3054:3074],
	2108: _auditConstant_name[3074:3094],
	2109: _auditConstant_name[3094:3124],
	2110: _auditConstant_name[3124:3146],
	2111: _auditConstant_name[3146:3166],
	2112: _auditConstant_name[3166:3181],
	2113: _auditConstant_name[3181:3199],
	2114: _auditConstant_name[3199:3218],
	2115: _auditConstant_name[3218:3237],
	2116: _auditConstant_name[3237:3256],
	2117: _auditConstant_name[3256:3277],
	2199: _auditConstant_name[3277:3296],
	2200: _auditConstant_name[3296:3317],
	2201: _auditConstant_name[3317:3333],
	2202: _auditConstant_name[3333:3353],
	2203: _auditConstant_name[3353:3375],
	2204: _auditConstant_name[3375:3397],
	2205: _auditConstant_name[3397:3423],
	2206: _auditConstant_name[3423:3451],
	2207: _auditConstant_name[3451:3471],
	2208: _auditConstant_name[3471:3491],
	2209: _auditConstant_name[3491:3508],
	2210: _auditConstant_name[3508:3523],
	2211: _auditConstant_name[3523:3540],
	2212: _auditConstant_name[3540:3555],
	2299: _auditConstant_name[3555:3575],
	2300: _auditConstant_name[3575:3600],
	2301: _auditConstant_name[3600:3617],
	2302: _auditConstant_name[3617:3634],
	2303: _auditConstant_name[3634:3654],
	2304: _auditConstant_name[3654:3678],
	2305: _auditConstant_name[3678:3703],
	2306: _auditConstant_name[3703:3730],
	2307: _auditConstant_name[3730:3745],
	2308: _auditConstant_name[3745:3762],
	2309: _auditConstant_name[3762:3778],
	2310: _auditConstant_name[3778:3804],
	2311: _auditConstant_name[3804:3821],
	2312: _auditConstant_name[3821:3849],
	2399: _auditConstant_name[3849:3873],
	2400: _auditConstant_name[3873:3895],
	2401: _auditConstant_name[3895:3925],
	2402: _auditConstant_name[3925:3943],
	2403: _auditConstant_name[3943:3962],
	2404: _auditConstant_name[3962:3983],
	2405: _auditConstant_name[3983:4008],
	2406: _auditConstant_name[4008:4032],
	2407: _auditConstant_name[4032:4052],
	2408: _auditConstant_name[4052:4071],
	2409: _auditConstant_name[4071:4092],
	2499: _auditConstant_name[4092:4113],
	2500: _auditConstant_name[4113:4133],
	2501: _auditConstant_name[4133:4152],
	2502: _auditConstant_name[4152:4173],
	2599: _auditConstant_name[4173:4192],
	2999: _auditConstant_name[4192:4212],
}

func (i auditConstant) String() string {
	if str, ok := _auditConstant_map[i]; ok {
		return str
	}
	return fmt.Sprintf("auditConstant(%d)", i)
}
