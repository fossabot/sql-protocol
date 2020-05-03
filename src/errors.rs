use std::error;
use std::result;
/// A shortcut to box an error.
#[macro_export]
macro_rules! box_err {
    ($e:expr) => ({
        let e: Box<dyn error::Error + Sync + Send> = format!("[{}:{}]: {}", file!(), line!(),  $e).into();
        e.into()
    });
    ($f:tt, $($arg:expr),+) => ({
        box_err!(format!($f, $($arg),+))
    });
}

quick_error! {
    #[derive(Debug)]
    pub enum ProtoError {
        Other(err: Box<dyn error::Error + Sync + Send>) {
            from()
            cause(err.as_ref())
            description(err.description())
            display("Unknown error: {:?}", err)
        }
        // Following is for From other errors.
        Io(err: std::io::Error) {
            from()
            cause(err)
            description(err.description())
            display("Io {}", err)
        }
        // Auth
        ReadClientFlagError {
            description("Read client flags error when unpacking packets")
        }
        ProtocolNotSupport {
            description("Only support protocol 4.1")
        }
        ReadMaxPacketSizeError {
            description("Read max packet size error when unpacking packets")
        }
        ReadCharsetError {
            description("Read charset error when unpacking packets")
        }
        ReadZeroError {
            description("Read zero error when unpacking packets")
        }
        ReadUserError {
            description("Read user error when unpacking packets")
        }
        ReadAuthResponseError {
            description("Read auth response error when unpacking packets")
        }
        ReadAuthResponseLengthError {
            description("Read auth response length error when unpacking packets")
        }
        ReadDatabaseError {
            description("Read database error when unpacking packets")
        }
        ReadPluginError {
            description("Read plugin name error when unpacking packets")
        }
        InvalidPluginError(s: String) {
            from()
            description(err.description())
            display("Invalid plugin name {}", s)
        }
        // Greeting
        ReadProtocolVersionError{
            description("Read protocol version error when unpacking packets")
        }
        ReadServerVersionError{
            description("Read server version error when unpacking packets")
        }
        ReadConnectionIdError{
            description("Read connection id error when unpacking packets")
        }
        ReadSaltError{
            description("Read salt error when unpacking packets")
        }
        ReadCapabilityFlagError{
            description("Read capability flag error when unpacking packets")
        }
        ReadStatusFlagError{
            description("Read status flag error when unpacking packets")
        }
        ReadAuthPluginLenError{
            description("Read auth plugin data length error when unpacking packets")
        }
        ParseComStatementError{
            description("Parse com statement error when unpacking packets")
        }
        ParseComSetOptionError{
            description("Parse com set option error when unpacking packets")
        }
        ReadNextPacketError{
            description("Read next packet error")
        }
        EmptyPacketError{
            description("Empty packet error")
        }
        MultiPacketNotSupport{
            description("Multi packet not support")
        }
        ComQuit{
            description("Com Quit")
        }
    }
}

pub type ProtoResult<T> = result::Result<T, ProtoError>;
