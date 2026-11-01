//! AFP protocol constants (AFP 2.2, as used by AppleShare Client 3.7/3.8).

// ---- command codes ----
pub const FP_BYTE_RANGE_LOCK: u8 = 1;
pub const FP_CLOSE_VOL: u8 = 2;
pub const FP_CLOSE_DIR: u8 = 3;
pub const FP_CLOSE_FORK: u8 = 4;
pub const FP_COPY_FILE: u8 = 5;
pub const FP_CREATE_DIR: u8 = 6;
pub const FP_CREATE_FILE: u8 = 7;
pub const FP_DELETE: u8 = 8;
pub const FP_ENUMERATE: u8 = 9;
pub const FP_FLUSH: u8 = 10;
pub const FP_FLUSH_FORK: u8 = 11;
pub const FP_GET_FORK_PARMS: u8 = 14;
pub const FP_GET_SRVR_INFO: u8 = 15;
pub const FP_GET_SRVR_PARMS: u8 = 16;
pub const FP_GET_VOL_PARMS: u8 = 17;
pub const FP_LOGIN: u8 = 18;
pub const FP_LOGIN_CONT: u8 = 19;
pub const FP_LOGOUT: u8 = 20;
pub const FP_MAP_ID: u8 = 21;
pub const FP_MAP_NAME: u8 = 22;
pub const FP_MOVE_AND_RENAME: u8 = 23;
pub const FP_OPEN_VOL: u8 = 24;
pub const FP_OPEN_DIR: u8 = 25;
pub const FP_OPEN_FORK: u8 = 26;
pub const FP_READ: u8 = 27;
pub const FP_RENAME: u8 = 28;
pub const FP_SET_DIR_PARMS: u8 = 29;
pub const FP_SET_FILE_PARMS: u8 = 30;
pub const FP_SET_FORK_PARMS: u8 = 31;
pub const FP_SET_VOL_PARMS: u8 = 32;
pub const FP_WRITE: u8 = 33;
pub const FP_GET_FILE_DIR_PARMS: u8 = 34;
pub const FP_SET_FILE_DIR_PARMS: u8 = 35;
pub const FP_CHANGE_PASSWORD: u8 = 36;
pub const FP_GET_USER_INFO: u8 = 37;
pub const FP_GET_SRVR_MSG: u8 = 38;
pub const FP_CREATE_ID: u8 = 39;
pub const FP_DELETE_ID: u8 = 40;
pub const FP_RESOLVE_ID: u8 = 41;
pub const FP_EXCHANGE_FILES: u8 = 42;
pub const FP_CAT_SEARCH: u8 = 43;
pub const FP_OPEN_DT: u8 = 48;
pub const FP_CLOSE_DT: u8 = 49;
pub const FP_GET_ICON: u8 = 51;
pub const FP_GET_ICON_INFO: u8 = 52;
pub const FP_ADD_APPL: u8 = 53;
pub const FP_REMOVE_APPL: u8 = 54;
pub const FP_GET_APPL: u8 = 55;
pub const FP_ADD_COMMENT: u8 = 56;
pub const FP_REMOVE_COMMENT: u8 = 57;
pub const FP_GET_COMMENT: u8 = 58;
pub const FP_ZZZZZ: u8 = 122;
pub const FP_ADD_ICON: u8 = 192;

pub fn command_name(cmd: u8) -> &'static str {
    match cmd {
        FP_BYTE_RANGE_LOCK => "FPByteRangeLock",
        FP_CLOSE_VOL => "FPCloseVol",
        FP_CLOSE_DIR => "FPCloseDir",
        FP_CLOSE_FORK => "FPCloseFork",
        FP_COPY_FILE => "FPCopyFile",
        FP_CREATE_DIR => "FPCreateDir",
        FP_CREATE_FILE => "FPCreateFile",
        FP_DELETE => "FPDelete",
        FP_ENUMERATE => "FPEnumerate",
        FP_FLUSH => "FPFlush",
        FP_FLUSH_FORK => "FPFlushFork",
        FP_GET_FORK_PARMS => "FPGetForkParms",
        FP_GET_SRVR_INFO => "FPGetSrvrInfo",
        FP_GET_SRVR_PARMS => "FPGetSrvrParms",
        FP_GET_VOL_PARMS => "FPGetVolParms",
        FP_LOGIN => "FPLogin",
        FP_LOGIN_CONT => "FPLoginCont",
        FP_LOGOUT => "FPLogout",
        FP_MAP_ID => "FPMapID",
        FP_MAP_NAME => "FPMapName",
        FP_MOVE_AND_RENAME => "FPMoveAndRename",
        FP_OPEN_VOL => "FPOpenVol",
        FP_OPEN_DIR => "FPOpenDir",
        FP_OPEN_FORK => "FPOpenFork",
        FP_READ => "FPRead",
        FP_RENAME => "FPRename",
        FP_SET_DIR_PARMS => "FPSetDirParms",
        FP_SET_FILE_PARMS => "FPSetFileParms",
        FP_SET_FORK_PARMS => "FPSetForkParms",
        FP_SET_VOL_PARMS => "FPSetVolParms",
        FP_WRITE => "FPWrite",
        FP_GET_FILE_DIR_PARMS => "FPGetFileDirParms",
        FP_SET_FILE_DIR_PARMS => "FPSetFileDirParms",
        FP_CHANGE_PASSWORD => "FPChangePassword",
        FP_GET_USER_INFO => "FPGetUserInfo",
        FP_GET_SRVR_MSG => "FPGetSrvrMsg",
        FP_CREATE_ID => "FPCreateID",
        FP_DELETE_ID => "FPDeleteID",
        FP_RESOLVE_ID => "FPResolveID",
        FP_EXCHANGE_FILES => "FPExchangeFiles",
        FP_CAT_SEARCH => "FPCatSearch",
        FP_OPEN_DT => "FPOpenDT",
        FP_CLOSE_DT => "FPCloseDT",
        FP_GET_ICON => "FPGetIcon",
        FP_GET_ICON_INFO => "FPGetIconInfo",
        FP_ADD_APPL => "FPAddAPPL",
        FP_REMOVE_APPL => "FPRemoveAPPL",
        FP_GET_APPL => "FPGetAPPL",
        FP_ADD_COMMENT => "FPAddComment",
        FP_REMOVE_COMMENT => "FPRemoveComment",
        FP_GET_COMMENT => "FPGetComment",
        FP_ZZZZZ => "FPZzzzz",
        FP_ADD_ICON => "FPAddIcon",
        _ => "FPUnknown",
    }
}

// ---- result codes ----
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum AfpError {
    AccessDenied = -5000,
    AuthContinue = -5001,
    BadUam = -5002,
    BadVersNum = -5003,
    BitmapErr = -5004,
    CantMove = -5005,
    DenyConflict = -5006,
    DirNotEmpty = -5007,
    DiskFull = -5008,
    EofErr = -5009,
    FileBusy = -5010,
    FlatVol = -5011,
    ItemNotFound = -5012,
    LockErr = -5013,
    MiscErr = -5014,
    NoMoreLocks = -5015,
    NoServer = -5016,
    ObjectExists = -5017,
    ObjectNotFound = -5018,
    ParamErr = -5019,
    RangeNotLocked = -5020,
    RangeOverlap = -5021,
    SessClosed = -5022,
    UserNotAuth = -5023,
    CallNotSupported = -5024,
    ObjectTypeErr = -5025,
    TooManyFilesOpen = -5026,
    ServerGoingDown = -5027,
    CantRename = -5028,
    DirNotFound = -5029,
    IconTypeError = -5030,
    VolLocked = -5031,
    ObjectLocked = -5032,
    ContainsSharedErr = -5033,
    IdNotFound = -5034,
    IdExists = -5035,
    DiffVolErr = -5036,
    CatalogChanged = -5037,
    SameObjectErr = -5038,
    BadIdErr = -5039,
    PwdSameErr = -5040,
    PwdTooShortErr = -5041,
    PwdExpiredErr = -5042,
    InsideSharedErr = -5043,
    InsideTrashErr = -5044,
    PwdNeedsChangeErr = -5045,
    PwdPolicyErr = -5046,
    DiskQuotaExceeded = -5047,
}

impl AfpError {
    pub fn code(self) -> i32 {
        self as i32
    }

    /// Map an OS error to the closest AFP error, as netatalk does.
    pub fn from_io(e: &std::io::Error) -> AfpError {
        match e.raw_os_error() {
            Some(libc::EACCES) | Some(libc::EPERM) => AfpError::AccessDenied,
            Some(libc::EROFS) => AfpError::VolLocked,
            Some(libc::ENOENT) | Some(libc::ENOTDIR) => AfpError::ObjectNotFound,
            Some(libc::EEXIST) => AfpError::ObjectExists,
            Some(libc::ENOTEMPTY) => AfpError::DirNotEmpty,
            Some(libc::ENOSPC) => AfpError::DiskFull,
            Some(libc::EDQUOT) => AfpError::DiskQuotaExceeded,
            Some(libc::EMFILE) | Some(libc::ENFILE) => AfpError::TooManyFilesOpen,
            Some(libc::EXDEV) => AfpError::CantMove,
            Some(libc::ENAMETOOLONG) => AfpError::ParamErr,
            Some(libc::EISDIR) => AfpError::ObjectTypeErr,
            Some(libc::EBUSY) | Some(libc::ETXTBSY) => AfpError::FileBusy,
            Some(libc::ELOOP) => AfpError::ObjectNotFound,
            _ => AfpError::MiscErr,
        }
    }
}

impl From<std::io::Error> for AfpError {
    fn from(e: std::io::Error) -> Self {
        AfpError::from_io(&e)
    }
}

pub type AfpResult<T> = Result<T, AfpError>;

// ---- FPGetSrvrInfo flags ----
pub const SRVR_SUPPORTS_COPYFILE: u16 = 1 << 0;
pub const SRVR_SUPPORTS_CHGPWD: u16 = 1 << 1;
pub const SRVR_NO_SAVE_PASSWORD: u16 = 1 << 2;
pub const SRVR_SUPPORTS_SRVR_MSG: u16 = 1 << 3;
pub const SRVR_SUPPORTS_SRVR_SIG: u16 = 1 << 4;
pub const SRVR_SUPPORTS_TCP: u16 = 1 << 5;
pub const SRVR_SUPPORTS_SRVR_NOTIFY: u16 = 1 << 6;

// ---- volume bitmap ----
pub const VOL_BIT_ATTR: u16 = 1 << 0;
pub const VOL_BIT_SIG: u16 = 1 << 1;
pub const VOL_BIT_CDATE: u16 = 1 << 2;
pub const VOL_BIT_MDATE: u16 = 1 << 3;
pub const VOL_BIT_BDATE: u16 = 1 << 4;
pub const VOL_BIT_VID: u16 = 1 << 5;
pub const VOL_BIT_BFREE: u16 = 1 << 6;
pub const VOL_BIT_BTOTAL: u16 = 1 << 7;
pub const VOL_BIT_NAME: u16 = 1 << 8;
pub const VOL_BIT_XBFREE: u16 = 1 << 9;
pub const VOL_BIT_XBTOTAL: u16 = 1 << 10;
pub const VOL_BIT_BSIZE: u16 = 1 << 11;
pub const VOL_BITS_VALID: u16 = 0x0FFF;

// ---- volume attributes ----
pub const VOLATTR_RO: u16 = 1 << 0;
pub const VOLATTR_PASSWD: u16 = 1 << 1;
pub const VOLATTR_FILE_ID: u16 = 1 << 2;
pub const VOLATTR_NO_EXCHANGE: u16 = 1 << 9;

// ---- file / directory bitmaps ----
pub const FIL_BIT_ATTR: u16 = 1 << 0;
pub const FIL_BIT_PDID: u16 = 1 << 1;
pub const FIL_BIT_CDATE: u16 = 1 << 2;
pub const FIL_BIT_MDATE: u16 = 1 << 3;
pub const FIL_BIT_BDATE: u16 = 1 << 4;
pub const FIL_BIT_FINFO: u16 = 1 << 5;
pub const FIL_BIT_LNAME: u16 = 1 << 6;
pub const FIL_BIT_SNAME: u16 = 1 << 7;
pub const FIL_BIT_FNUM: u16 = 1 << 8;
pub const FIL_BIT_DFLEN: u16 = 1 << 9;
pub const FIL_BIT_RFLEN: u16 = 1 << 10;
pub const FIL_BIT_XDFLEN: u16 = 1 << 11;
pub const FIL_BIT_PDINFO: u16 = 1 << 13;
pub const FIL_BIT_XRFLEN: u16 = 1 << 14;

pub const DIR_BIT_ATTR: u16 = 1 << 0;
pub const DIR_BIT_PDID: u16 = 1 << 1;
pub const DIR_BIT_CDATE: u16 = 1 << 2;
pub const DIR_BIT_MDATE: u16 = 1 << 3;
pub const DIR_BIT_BDATE: u16 = 1 << 4;
pub const DIR_BIT_FINFO: u16 = 1 << 5;
pub const DIR_BIT_LNAME: u16 = 1 << 6;
pub const DIR_BIT_SNAME: u16 = 1 << 7;
pub const DIR_BIT_DID: u16 = 1 << 8;
pub const DIR_BIT_OFFCNT: u16 = 1 << 9;
pub const DIR_BIT_UID: u16 = 1 << 10;
pub const DIR_BIT_GID: u16 = 1 << 11;
pub const DIR_BIT_ACCESS: u16 = 1 << 12;
pub const DIR_BIT_PDINFO: u16 = 1 << 13;

/// Bits AFP 2.2 clients may request for files.
pub const FIL_BITS_VALID: u16 = 0x27FF;
/// Bits AFP 2.2 clients may request for directories.
pub const DIR_BITS_VALID: u16 = 0x3FFF;

// ---- file / dir attributes ----
pub const ATTR_INVISIBLE: u16 = 1 << 0;
pub const ATTR_MULTIUSER: u16 = 1 << 1; // files; IsExpFolder on dirs
pub const ATTR_SYSTEM: u16 = 1 << 2;
pub const ATTR_DOPEN: u16 = 1 << 3;
pub const ATTR_ROPEN: u16 = 1 << 4;
pub const ATTR_NOWRITE: u16 = 1 << 5; // WriteInhibit
pub const ATTR_BACKUP: u16 = 1 << 6;
pub const ATTR_NORENAME: u16 = 1 << 7;
pub const ATTR_NODELETE: u16 = 1 << 8;
pub const ATTR_NOCOPY: u16 = 1 << 10;
pub const ATTR_SETCLR: u16 = 1 << 15;

// ---- access rights (directory) ----
pub const AR_USEARCH: u32 = 1 << 0;
pub const AR_UREAD: u32 = 1 << 1;
pub const AR_UWRITE: u32 = 1 << 2;
pub const AR_UOWN: u32 = 1 << 7;

// ---- fork open modes ----
pub const OPENACC_RD: u16 = 1 << 0;
pub const OPENACC_WR: u16 = 1 << 1;
pub const OPENACC_DRD: u16 = 1 << 4;
pub const OPENACC_DWR: u16 = 1 << 5;

// ---- path types ----
pub const PATH_SHORT: u8 = 1;
pub const PATH_LONG: u8 = 2;

// ---- special directory IDs ----
pub const DIRID_PARENT_OF_ROOT: u32 = 1;
pub const DIRID_ROOT: u32 = 2;

/// Seconds between 1970-01-01 and 2000-01-01, the AFP epoch.
pub const AFP_EPOCH_DELTA: i64 = 946_684_800;
/// AFP date meaning "never" (used for backup dates).
pub const AFP_DATE_NEVER: u32 = 0x8000_0000;

pub fn unix_to_afp_date(t: i64) -> u32 {
    let d = t - AFP_EPOCH_DELTA;
    d.clamp(i32::MIN as i64 + 1, i32::MAX as i64) as i32 as u32
}

pub fn afp_to_unix_date(d: u32) -> i64 {
    (d as i32) as i64 + AFP_EPOCH_DELTA
}
