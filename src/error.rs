use std::fmt;
use std::io;

#[derive(Debug)]
pub enum QsrlError {
    Io { context: String, source: io::Error },
    Usage(String),
    InvalidFormat(String),
    Parse(String),
    UnsupportedVersion(u16),
    UnsupportedAlgorithm(String),
    UnsupportedFeature(String),
    MissingSignature(String),
    SignatureVerificationFailed(String),
    DataCorruption(String),
    KeyRejected(String),
}

pub type Result<T> = std::result::Result<T, QsrlError>;

impl QsrlError {
    pub fn io(context: impl Into<String>, source: io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }

    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Usage(_) => 2,
            Self::SignatureVerificationFailed(_) | Self::MissingSignature(_) => 3,
            Self::DataCorruption(_) => 4,
            Self::UnsupportedVersion(_)
            | Self::UnsupportedAlgorithm(_)
            | Self::UnsupportedFeature(_) => 5,
            _ => 1,
        }
    }
}

impl fmt::Display for QsrlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { context, source } => write!(f, "{context}: {source}"),
            Self::Usage(message)
            | Self::InvalidFormat(message)
            | Self::Parse(message)
            | Self::UnsupportedAlgorithm(message)
            | Self::UnsupportedFeature(message)
            | Self::MissingSignature(message)
            | Self::SignatureVerificationFailed(message)
            | Self::DataCorruption(message)
            | Self::KeyRejected(message) => f.write_str(message),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported QSRL format version {version}")
            }
        }
    }
}

impl std::error::Error for QsrlError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}
