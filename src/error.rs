use std::fmt;

pub const ERR_EPERM: i32 = 1;
pub const ERR_ENOENT: i32 = 2;
pub const ERR_EACCES: i32 = 13;
pub const ERR_EEXIST: i32 = 17;
pub const ERR_EXDEV: i32 = 18;
pub const ERR_EINVAL: i32 = 22;
pub const ERR_EWOULDBLOCK: i32 = 35;
pub const ERR_ENOTSUP: i32 = 45;
pub const ERR_USAGE: i32 = 64;
pub const ERR_ESTALE: i32 = 70;
pub const EXIT_FUSE_TRIPPED: i32 = 99;

#[derive(Debug, Clone)]
pub struct AfuseError {
    pub code: i32,
    pub message: String,
}

impl AfuseError {
    pub fn new(code: i32, msg: impl Into<String>) -> Self {
        Self {
            code,
            message: msg.into(),
        }
    }
}

impl fmt::Display for AfuseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[errno={}] {}", self.code, self.message)
    }
}

impl std::error::Error for AfuseError {}
