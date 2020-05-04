use crate::constants::CapabilityFlag::{
    CapabilityClientConnAttr, CapabilityClientConnectWithDB, CapabilityClientDeprecateEOF,
    CapabilityClientLongFlag, CapabilityClientLongPassword, CapabilityClientMultiResults,
    CapabilityClientMultiStatements, CapabilityClientPluginAuth,
    CapabilityClientPluginAuthLenencClientData, CapabilityClientProtocol41,
    CapabilityClientSecureConnection, CapabilityClientTransactions,
};

// MAX_PACKET_SIZE is the maximum payload length of a packet the server supports.
pub const MAX_PACKET_SIZE: usize = (1 << 24) - 1;
// PROTOCOL_VERSION is current version of the protocol.
// Always 10.
pub const PROTOCOL_VERSION: u8 = 10;

// MYSQL_NATIVE_PASSWORD uses a salt and transmits a hash on the wire.
pub const MYSQL_NATIVE_PASSWORD: &'static str = "mysql_native_password";
// MYSQL_CLEAR_PASSWORD transmits the password in the clear.
pub const MYSQL_CLEAR_PASSWORD: &'static str = "mysql_clear_password";
// MYSQL_DIALOG uses the dialog plugin on the client side. It transmits data in the clear.
pub const MYSQL_DIALOG: &'static str = "dialog";

// See http://dev.mysql.com/doc/internals/en/character-set.html#packet-Protocol::CharacterSet
pub const CHARACTER_SET_UTF8: u8 = 33;
pub const CHARACTER_SET_BINARY: i32 = 63;
// See http://dev.mysql.com/doc/internals/en/status-flags.html
pub const SERVER_STATUS_AUTOCOMMIT: u16 = 0x0002;

// Packet
pub const OK_PACKET: u8 = 0x00;
pub const ERR_PACKET: u8 = 0xff;
pub const EOF_PACKET: u8 = 0xff;

//flags
pub const SERVER_MORE_RESULTS_EXISTS: u16 = 0x0008;

// Originally found in include/mysql/mysql_com.h
#[allow(dead_code)]
pub enum CapabilityFlag {
    // CapabilityClientLongPassword is CLIENT_LONG_PASSWORD.
    // New more secure passwords. Assumed to be set since 4.1.1.
    // We do not check this anywhere.
    CapabilityClientLongPassword = 1,

    // CapabilityClientFoundRows is CLIENT_FOUND_ROWS.
    CapabilityClientFoundRows = 1 << 1,

    // CapabilityClientLongFlag is CLIENT_LONG_FLAG.
    // Longer flags in Protocol::ColumnDefinition320.
    // Set it everywhere, not used, as we use Protocol::ColumnDefinition41.
    CapabilityClientLongFlag = 1 << 2,

    // CapabilityClientConnectWithDB is CLIENT_CONNECT_WITH_DB.
    // One can specify db on connect.
    CapabilityClientConnectWithDB = 1 << 3,

    // CLIENT_NO_SCHEMA 1 << 4
    // Do not permit database.table.column. We do permit it.

    // CLIENT_COMPRESS 1 << 5
    // We do not support compression. CPU is usually our bottleneck.

    // CLIENT_ODBC 1 << 6
    // No special behavior since 3.22.

    // CLIENT_LOCAL_FILES 1 << 7
    // Client can use LOCAL INFILE request of LOAD DATA|XML.
    // We do not set it.

    // CLIENT_IGNORE_SPACE 1 << 8
    // Parser can ignore spaces before '('.
    // We ignore this.

    // CapabilityClientProtocol41 is CLIENT_PROTOCOL_41.
    // New 4.1 protocol. Enforced everywhere.
    CapabilityClientProtocol41 = 1 << 9,

    // CLIENT_INTERACTIVE 1 << 10
    // Not specified, ignored.

    // CapabilityClientSSL is CLIENT_SSL.
    // Switch to SSL after handshake.
    CapabilityClientSSL = 1 << 11,

    // CLIENT_IGNORE_SIGPIPE 1 << 12
    // Do not issue SIGPIPE if network failures occur (libmysqlclient only).

    // CapabilityClientTransactions is CLIENT_TRANSACTIONS.
    // Can send status flags in EOF_Packet.
    // This flag is optional in 3.23, but always set by the server since 4.0.
    // We just do it all the time.
    CapabilityClientTransactions = 1 << 13,

    // CLIENT_RESERVED 1 << 14

    // CapabilityClientSecureConnection is CLIENT_SECURE_CONNECTION.
    // New 4.1 authentication. Always set, expected, never checked.
    CapabilityClientSecureConnection = 1 << 15,

    // CapabilityClientMultiStatements is CLIENT_MULTI_STATEMENTS
    // Can handle multiple statements per ComQuery and ComStmtPrepare.
    CapabilityClientMultiStatements = 1 << 16,

    // CapabilityClientMultiResults is CLIENT_MULTI_RESULTS
    // Can send multiple resultsets for ComQuery.
    CapabilityClientMultiResults = 1 << 17,

    // CapabilityClientPluginAuth is CLIENT_PLUGIN_AUTH.
    // Client supports plugin authentication.
    CapabilityClientPluginAuth = 1 << 19,

    // CapabilityClientConnAttr is CLIENT_CONNECT_ATTRS
    // Permits connection attributes in Protocol::HandshakeResponse41.
    CapabilityClientConnAttr = 1 << 20,

    // CapabilityClientPluginAuthLenencClientData is CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
    CapabilityClientPluginAuthLenencClientData = 1 << 21,

    // CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS 1 << 22
    // Announces support for expired password extension.
    // Not yet supported.

    // CLIENT_SESSION_TRACK 1 << 23
    // Can set SERVER_SESSION_STATE_CHANGED in the Status Flags
    // and send session-state change data after a OK packet.
    // Not yet supported.

    // CapabilityClientDeprecateEOF is CLIENT_DEPRECATE_EOF
    // Expects an OK (instead of EOF) after the resultset rows of a Text Resultset.
    CapabilityClientDeprecateEOF = 1 << 24,
}

// See https://dev.mysql.com/doc/internals/en/command-phase.html
#[derive(Copy, Clone)]
pub enum PacketType {
    ComSleep,
    ComQuit,
    ComInitDB,
    ComQuery,
    ComFieldList,
    ComCreateDb,
    ComDropDb,
    ComRefresh,
    ComShutdown,
    ComStatistics,
    ComProcessInfo,
    ComConnect,
    ComProcessKill,
    ComDebug,
    ComPing,
    ComTime,
    ComDelayedInsert,
    ComChangeUser,
    ComBinlogDump,
    ComTableDump,
    ComConnectOut,
    ComRegisterSlave,
    ComStmtPrepare,
    ComStmtExecute,
    ComStmtSendLongData,
    ComStmtClose,
    ComStmtReset,
    ComSetOption,
    ComStmtFetch,
    ComDaemon,
    ComBinlogDumpGtid,
    ComResetConnection,
}

impl Into<&'static str> for PacketType {
    fn into(self) -> &'static str {
        return match self {
            PacketType::ComSleep => "COM_SLEEP",
            PacketType::ComQuit => "COM_QUIT",
            PacketType::ComInitDB => "COM_INIT_DB",
            PacketType::ComQuery => "COM_QUERY",
            PacketType::ComFieldList => "COM_FIELD_LIST",
            PacketType::ComCreateDb => "COM_CREATE_DB",
            PacketType::ComDropDb => "COM_DROP_DB",
            PacketType::ComRefresh => "COM_REFRESH",
            PacketType::ComShutdown => "COM_SHUTDOWN",
            PacketType::ComStatistics => "COM_STATISTICS",
            PacketType::ComProcessInfo => "COM_PROCESS_INFO",
            PacketType::ComConnect => "COM_CONNECT",
            PacketType::ComProcessKill => "COM_PROCESS_KILL",
            PacketType::ComDebug => "COM_DEBUG",
            PacketType::ComPing => "COM_PING",
            PacketType::ComTime => "COM_TIME",
            PacketType::ComDelayedInsert => "COM_DELAYED_INSERT",
            PacketType::ComChangeUser => "COM_CHANGE_USER",
            PacketType::ComBinlogDump => "COM_BINLOG_DUMP",
            PacketType::ComTableDump => "COM_TABLE_DUMP",
            PacketType::ComConnectOut => "COM_CONNECT_OUT",
            PacketType::ComRegisterSlave => "COM_REGISTER_SLAVE",
            PacketType::ComStmtPrepare => "COM_STMT_PREPARE",
            PacketType::ComStmtExecute => "COM_STMT_EXECUTE",
            PacketType::ComStmtSendLongData => "COM_STMT_SEND_LONG_DATA",
            PacketType::ComStmtClose => "COM_STMT_CLOSE",
            PacketType::ComStmtReset => "COM_STMT_RESET",
            PacketType::ComSetOption => "COM_SET_OPTION",
            PacketType::ComStmtFetch => "COM_STMT_FETCH",
            PacketType::ComDaemon => "COM_DAEMON",
            PacketType::ComBinlogDumpGtid => "COM_BINLOG_DUMP_GTID",
            PacketType::ComResetConnection => "COM_RESET_CONNECTION",
        };
    }
}

impl ToString for PacketType {
    fn to_string(&self) -> String {
        let c: &'static str = (*self).into();
        c.to_string()
    }
}

impl Into<u16> for PacketType {
    fn into(self) -> u16 {
        return match self {
            PacketType::ComSleep => 0x00,
            PacketType::ComQuit => 0x01,
            PacketType::ComInitDB => 0x02,
            PacketType::ComQuery => 0x03,
            PacketType::ComFieldList => 0x04,
            PacketType::ComCreateDb => 0x05,
            PacketType::ComDropDb => 0x06,
            PacketType::ComRefresh => 0x07,
            PacketType::ComShutdown => 0x08,
            PacketType::ComStatistics => 0x09,
            PacketType::ComProcessInfo => 0x0a,
            PacketType::ComConnect => 0x0b,
            PacketType::ComProcessKill => 0x0c,
            PacketType::ComDebug => 0x0d,
            PacketType::ComPing => 0x0e,
            PacketType::ComTime => 0x0f,
            PacketType::ComDelayedInsert => 0x10,
            PacketType::ComChangeUser => 0x11,
            PacketType::ComBinlogDump => 0x12,
            PacketType::ComTableDump => 0x13,
            PacketType::ComConnectOut => 0x14,
            PacketType::ComRegisterSlave => 0x15,
            PacketType::ComStmtPrepare => 0x16,
            PacketType::ComStmtExecute => 0x17,
            PacketType::ComStmtSendLongData => 0x18,
            PacketType::ComStmtClose => 0x19,
            PacketType::ComStmtReset => 0x1a,
            PacketType::ComSetOption => 0x1b,
            PacketType::ComStmtFetch => 0x1c,
            PacketType::ComDaemon => 0x1d,
            PacketType::ComBinlogDumpGtid => 0x1e,
            PacketType::ComResetConnection => 0x1f,
        };
    }
}

impl From<u64> for PacketType {
    fn from(integer: u64) -> Self {
        return match integer {
            0x00 => PacketType::ComSleep,
            0x01 => PacketType::ComQuit,
            0x02 => PacketType::ComInitDB,
            0x03 => PacketType::ComQuery,
            0x04 => PacketType::ComFieldList,
            0x05 => PacketType::ComCreateDb,
            0x06 => PacketType::ComDropDb,
            0x07 => PacketType::ComRefresh,
            0x08 => PacketType::ComShutdown,
            0x09 => PacketType::ComStatistics,
            0x0a => PacketType::ComProcessInfo,
            0x0b => PacketType::ComConnect,
            0x0c => PacketType::ComProcessKill,
            0x0d => PacketType::ComDebug,
            0x0e => PacketType::ComPing,
            0x0f => PacketType::ComTime,
            0x10 => PacketType::ComDelayedInsert,
            0x11 => PacketType::ComChangeUser,
            0x12 => PacketType::ComBinlogDump,
            0x13 => PacketType::ComTableDump,
            0x14 => PacketType::ComConnectOut,
            0x15 => PacketType::ComRegisterSlave,
            0x16 => PacketType::ComStmtPrepare,
            0x17 => PacketType::ComStmtExecute,
            0x18 => PacketType::ComStmtSendLongData,
            0x19 => PacketType::ComStmtClose,
            0x1a => PacketType::ComStmtReset,
            0x1b => PacketType::ComSetOption,
            0x1c => PacketType::ComStmtFetch,
            0x1d => PacketType::ComDaemon,
            0x1e => PacketType::ComBinlogDumpGtid,
            0x1f => PacketType::ComResetConnection,
            _ => {
                panic!("Unknown packet type");
            }
        };
    }
}

macro_rules! impl_from {
    ($t:ty) => {
        impl From<$t> for PacketType {
            fn from(v: $t) -> Self {
                (v as u64).into()
            }
        }
    };
}

impl_from!(u8);
impl_from!(u16);
impl_from!(u32);
impl_from!(usize);

// Error codes for client-side errors.
// Originally found in include/mysql/errmsg.h and
// https://dev.mysql.com/doc/refman/5.7/en/error-messages-client.html
#[allow(dead_code)]
enum ClientError {
    // CRUnknownError is CR_UNKNOWN_ERROR
    CRUnknownError = 2000,
    // CRConnectionError is CR_CONNECTION_ERROR
    // This is returned if a connection via a Unix socket fails.
    CRConnectionError = 2002,
    // CRConnHostError is CR_CONN_HOST_ERROR
    // This is returned if a connection via a TCP socket fails.
    CRConnHostError = 2003,
    // CRServerGone is CR_SERVER_GONE_ERROR.
    // This is returned if the client tries to send a command but it fails.
    CRServerGone = 2006,
    // CRVersionError is CR_VERSION_ERROR
    // This is returned if the server versions don't match what we support.
    CRVersionError = 2007,
    // CRServerHandshakeErr is CR_SERVER_HANDSHAKE_ERR
    CRServerHandshakeErr = 2012,
    // CRServerLost is CR_SERVER_LOST.
    // Used when:
    // - the client cannot write an initial auth packet.
    // - the client cannot read an initial auth packet.
    // - the client cannot read a response from the server.
    CRServerLost = 2013,
    // CRCommandsOutOfSync is CR_COMMANDS_OUT_OF_SYNC
    // Sent when the streaming calls are not done in the right order.
    CRCommandsOutOfSync = 2014,
    // CRNamedPipeStateError is CR_NAMEDPIPESETSTATE_ERROR.
    // This is the highest possible number for a connection error.
    CRNamedPipeStateError = 2018,
    // CRCantReadCharset is CR_CANT_READ_CHARSET
    CRCantReadCharset = 2019,
    // CRSSLConnectionError is CR_SSL_CONNECTION_ERROR
    CRSSLConnectionError = 2026,
    // CRMalformedPacket is CR_MALFORMED_PACKET
    CRMalformedPacket = 2027,
}

// Error codes for server-side errors.
// Originally found in include/mysql/mysqld_error.h and
// https://dev.mysql.com/doc/refman/5.7/en/error-messages-server.html
// The below are in sorted order by value, grouped by vterror code they should be bucketed into.
// See above reference for more information on each code.
#[allow(dead_code)]
pub enum ServerError {
    // unknown
    ERUnknownError = 1105,
    // unimplemented
    ERNotSupportedYet = 1235,
    // resource exhausted
    ERDiskFull = 1021,
    EROutOfMemory = 1037,
    EROutOfSortMemory = 1038,
    ERConCount = 1040,
    EROutOfResources = 1041,
    ERRecordFileFull = 1114,
    ERHostIsBlocked = 1129,
    ERCantCreateThread = 1135,
    ERTooManyDelayedThreads = 1151,
    ERNetPacketTooLarge = 1153,
    ERTooManyUserConnections = 1203,
    ERLockTableFull = 1206,
    ERUserLimitReached = 1226,
    // deadline exceeded
    ERLockWaitTimeout = 1205,
    // unavailable
    ERServerShutdown = 1053,
    // not found
    ERFormNotFound = 1029,
    ERKeyNotFound = 1032,
    ERBadFieldError = 1054,
    ERNoSuchThread = 1094,
    ERUnknownTable = 1109,
    ERCantFindUDF = 1122,
    ERNonExistingGrant = 1141,
    ERNoSuchTable = 1146,
    ERNonExistingTableGrant = 1147,
    ERKeyDoesNotExist = 1176,
    // permissions
    ERDBAccessDenied = 1044,
    ERAccessDeniedError = 1045,
    ERKillDenied = 1095,
    ERNoPermissionToCreateUsers = 1211,
    ERSpecifiedAccessDenied = 1227,
    // failed precondition
    ERNoDb = 1046,
    ERNoSuchIndex = 1082,
    ERCantDropFieldOrKey = 1091,
    ERTableNotLockedForWrite = 1099,
    ERTableNotLocked = 1100,
    ERTooBigSelect = 1104,
    ERNotAllowedCommand = 1148,
    ERTooLongString = 1162,
    ERDelayedInsertTableLocked = 1165,
    ERDupUnique = 1169,
    ERRequiresPrimaryKey = 1173,
    ERCantDoThisDuringAnTransaction = 1179,
    ERReadOnlyTransaction = 1207,
    ERCannotAddForeign = 1215,
    ERNoReferencedRow = 1216,
    ERRowIsReferenced = 1217,
    ERCantUpdateWithReadLock = 1223,
    ERNoDefault = 1230,
    EROperandColumns = 1241,
    ERSubqueryNo1Row = 1242,
    ERNonUpdateableTable = 1288,
    ERFeatureDisabled = 1289,
    EROptionPreventsStatement = 1290,
    ERDuplicatedValueInType = 1291,
    ERRowIsReferenced2 = 1451,
    ErNoReferencedRow2 = 1452,
    // already exists
    ERTableExists = 1050,
    ERDupEntry = 1062,
    ERFileExists = 1086,
    ERUDFExists = 1125,
    // aborted
    ERGotSignal = 1078,
    ERForcingClose = 1080,
    ERAbortingConnection = 1152,
    ERLockDeadlock = 1213,
    // invalid arg
    ERUnknownComError = 1047,
    ERBadNullError = 1048,
    ERBadDb = 1049,
    ERBadTable = 1051,
    ERNonUniq = 1052,
    ERWrongFieldWithGroup = 1055,
    ERWrongGroupField = 1056,
    ERWrongSumSelect = 1057,
    ERWrongValueCount = 1058,
    ERTooLongIdent = 1059,
    ERDupFieldName = 1060,
    ERDupKeyName = 1061,
    ERWrongFieldSpec = 1063,
    ERParseError = 1064,
    EREmptyQuery = 1065,
    ERNonUniqTable = 1066,
    ERInvalidDefault = 1067,
    ERMultiplePriKey = 1068,
    ERTooManyKeys = 1069,
    ERTooManyKeyParts = 1070,
    ERTooLongKey = 1071,
    ERKeyColumnDoesNotExist = 1072,
    ERBlobUsedAsKey = 1073,
    ERTooBigFieldLength = 1074,
    ERWrongAutoKey = 1075,
    ERWrongFieldTerminators = 1083,
    ERBlobsAndNoTerminated = 1084,
    ERTextFileNotReadable = 1085,
    ERWrongSubKey = 1089,
    ERCantRemoveAllFields = 1090,
    ERUpdateTableUsed = 1093,
    ERNoTablesUsed = 1096,
    ERTooBigSet = 1097,
    ERBlobCantHaveDefault = 1101,
    ERWrongDbName = 1102,
    ERWrongTableName = 1103,
    ERUnknownProcedure = 1106,
    ERWrongParamCountToProcedure = 1107,
    ERWrongParametersToProcedure = 1108,
    ERFieldSpecifiedTwice = 1110,
    ERInvalidGroupFuncUse = 1111,
    ERTableMustHaveColumns = 1113,
    ERUnknownCharacterSet = 1115,
    ERTooManyTables = 1116,
    ERTooManyFields = 1117,
    ERTooBigRowSize = 1118,
    ERWrongOuterJoin = 1120,
    ERNullColumnInIndex = 1121,
    ERFunctionNotDefined = 1128,
    ERWrongValueCountOnRow = 1136,
    ERInvalidUseOfNull = 1138,
    ERRegexpError = 1139,
    ERMixOfGroupFuncAndFields = 1140,
    ERIllegalGrantForTable = 1144,
    ERSyntaxError = 1149,
    ERWrongColumnName = 1166,
    ERWrongKeyColumn = 1167,
    ERBlobKeyWithoutLength = 1170,
    ERPrimaryCantHaveNull = 1171,
    ERTooManyRows = 1172,
    ERUnknownSystemVariable = 1193,
    ERSetConstantsOnly = 1204,
    ERWrongArguments = 1210,
    ERWrongUsage = 1221,
    ERWrongNumberOfColumnsInSelect = 1222,
    ERDupArgument = 1225,
    ERLocalVariable = 1228,
    ERGlobalVariable = 1229,
    ERWrongValueForVar = 1231,
    ERWrongTypeForVar = 1232,
    ERVarCantBeRead = 1233,
    ERCantUseOptionHere = 1234,
    ERIncorrectGlobalLocalVar = 1238,
    ERWrongFKDef = 1239,
    ERKeyRefDoNotMatchTableRef = 1240,
    ERCyclicReference = 1245,
    ERCollationCharsetMismatch = 1253,
    ERCantAggregate2Collations = 1267,
    ERCantAggregate3Collations = 1270,
    ERCantAggregateNCollations = 1271,
    ERVariableIsNotStruct = 1272,
    ERUnknownCollation = 1273,
    ERWrongNameForIndex = 1280,
    ERWrongNameForCatalog = 1281,
    ERBadFTColumn = 1283,
    ERTruncatedWrongValue = 1292,
    ERTooMuchAutoTimestampCols = 1293,
    ERInvalidOnUpdate = 1294,
    ERUnknownTimeZone = 1298,
    ERInvalidCharacterString = 1300,
    ERIllegalReference = 1247,
    ERDerivedMustHaveAlias = 1248,
    ERTableNameNotAllowedHere = 1250,
    ERQueryInterrupted = 1317,
    ERTruncatedWrongValueForField = 1366,
    ERDataTooLong = 1406,
    ERDataOutOfRange = 1690,
}

// Sql states for errors.
// Originally found in include/mysql/sql_state.h
#[allow(dead_code)]
pub enum StateError {
    // SSUnknownSqlstate is ER_SIGNAL_EXCEPTION in
    // include/mysql/sql_state.h, but:
    // const char *unknown_sqlstate= "HY000"
    // in client.c. So using that one.
    SSUnknownSQLState,
    // SSUnknownComError is ER_UNKNOWN_COM_ERROR
    SSUnknownComError,
    // SSHandshakeError is ER_HANDSHAKE_ERROR
    SSHandshakeError,
    // SSServerShutdown is ER_SERVER_SHUTDOWN
    SSServerShutdown,
    // SSDataTooLong is ER_DATA_TOO_LONG
    SSDataTooLong,
    // SSDataOutOfRange is ER_DATA_OUT_OF_RANGE
    SSDataOutOfRange,
    // SSBadNullError is ER_BAD_NULL_ERROR
    SSBadNullError,
    // SSBadFieldError is ER_BAD_FIELD_ERROR
    SSBadFieldError,
    // SSDupKey is ER_DUP_KEY
    SSDupKey,
    // SSCantDoThisDuringAnTransaction is
    // ER_CANT_DO_THIS_DURING_AN_TRANSACTION
    SSCantDoThisDuringAnTransaction,
    // SSAccessDeniedError is ER_ACCESS_DENIED_ERROR
    SSAccessDeniedError,
    // SSLockDeadlock is ER_LOCK_DEADLOCK
    SSLockDeadlock,
}

impl Into<&'static str> for StateError {
    fn into(self) -> &'static str {
        return match self {
            StateError::SSUnknownSQLState => "HY000",
            StateError::SSUnknownComError => "08S01",
            StateError::SSHandshakeError => "08S01",
            StateError::SSServerShutdown => "08S01",
            StateError::SSDataTooLong => "22001",
            StateError::SSDataOutOfRange => "22003",
            StateError::SSBadNullError => "23000",
            StateError::SSBadFieldError => "42S22",
            StateError::SSDupKey => "23000",
            StateError::SSCantDoThisDuringAnTransaction => "25000",
            StateError::SSAccessDeniedError => "28000",
            StateError::SSLockDeadlock => "40001",
        };
    }
}

impl Into<String> for StateError {
    fn into(self) -> String {
        let s: &'static str = self.into();
        s.into()
    }
}

// CharacterSetMap maps the charset name (used in ConnParams) to the
// integer value.  Interesting ones have their own constant above.
fn convert_character_value(c: &str) -> i32 {
    return match c {
        "big5" => 1,
        "dec8" => 3,
        "cp850" => 4,
        "hp8" => 6,
        "koi8r" => 7,
        "latin1" => 8,
        "latin2" => 9,
        "swe7" => 10,
        "ascii" => 11,
        "ujis" => 12,
        "sjis" => 13,
        "hebrew" => 16,
        "tis620" => 18,
        "euckr" => 19,
        "koi8u" => 22,
        "gb2312" => 24,
        "greek" => 25,
        "cp1250" => 26,
        "gbk" => 28,
        "latin5" => 30,
        "armscii8" => 32,
        "utf8" => CHARACTER_SET_UTF8 as i32,
        "ucs2" => 35,
        "cp866" => 36,
        "keybcs2" => 37,
        "macce" => 38,
        "macroman" => 39,
        "cp852" => 40,
        "latin7" => 41,
        "utf8mb4" => 45,
        "cp1251" => 51,
        "utf16" => 54,
        "utf16le" => 56,
        "cp1256" => 57,
        "cp1257" => 59,
        "utf32" => 60,
        "binary" => CHARACTER_SET_BINARY,
        "geostd8" => 92,
        "cp932" => 95,
        "eucjpms" => 97,
        _ => {
            panic!("Unexpected character");
        }
    };
}

fn is_conn_err(num: i32) -> bool {
    (num >= ClientError::CRUnknownError as i32 && num <= ClientError::CRNamedPipeStateError as i32)
        || num == ServerError::ERQueryInterrupted as i32
}

pub const DEFAULT_CLIENT_CAPABILITY: u32 = CapabilityClientLongPassword as u32
    | CapabilityClientLongFlag as u32
    | CapabilityClientProtocol41 as u32
    | CapabilityClientTransactions as u32
    | CapabilityClientMultiStatements as u32
    | CapabilityClientPluginAuth as u32
    | CapabilityClientDeprecateEOF as u32
    | CapabilityClientSecureConnection as u32;

pub const DEFAULT_SERVER_CAPABILITY: u32 = CapabilityClientLongPassword as u32
    | CapabilityClientLongFlag as u32
    | CapabilityClientConnectWithDB as u32
    | CapabilityClientProtocol41 as u32
    | CapabilityClientTransactions as u32
    | CapabilityClientSecureConnection as u32
    | CapabilityClientMultiStatements as u32
    | CapabilityClientMultiResults as u32
    | CapabilityClientPluginAuth as u32
    | CapabilityClientPluginAuthLenencClientData as u32
    | CapabilityClientDeprecateEOF as u32
    | CapabilityClientConnAttr as u32;

pub const DEFAULT_SALT: &'static [u8; 20] = &[
    0x77, 0x63, 0x6a, 0x6d, 0x61, 0x22, 0x23, 0x27, // first part
    0x38, 0x26, 0x55, 0x58, 0x3b, 0x5d, 0x44, 0x78, 0x53, 0x73, 0x6b, 0x41,
];

pub enum TLSVersion {
    VersionTLS10 = 0x0301,
    VersionTLS11 = 0x0302,
    VersionTLS12 = 0x0303,
    VersionTLS13 = 0x0304,
    VersionSSL30 = 0x0300,
}

impl From<u64> for TLSVersion {
    fn from(ver: u64) -> Self {
        match ver {
            0x0301 => TLSVersion::VersionTLS10,
            0x0302 => TLSVersion::VersionTLS11,
            0x0303 => TLSVersion::VersionTLS12,
            0x0304 => TLSVersion::VersionTLS13,
            0x0300 => TLSVersion::VersionSSL30,
            _ => panic!("Unexpected version"),
        }
    }
}

macro_rules! impl_from_d {
    ($t:ty,$s:ty) => {
        impl From<$t> for $s {
            fn from(v: $t) -> Self {
                (v as u64).into()
            }
        }
    };
}

impl_from_d!(u8, TLSVersion);
impl_from_d!(u16, TLSVersion);
impl_from_d!(u32, TLSVersion);
impl_from_d!(usize, TLSVersion);
