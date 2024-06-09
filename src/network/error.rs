use nix::errno::Errno;

#[derive(Debug)]
pub enum NetworkError {
    IoError(String),
    InvalidName(String),
    InvalidSubnetMask(String),
    IoctlError(Errno),
    PacketParseError(String),
}

impl std::fmt::Display for NetworkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Network Error: {self:?}")
    }
}

impl std::error::Error for NetworkError {}
