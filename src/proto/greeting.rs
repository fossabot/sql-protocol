use std::io::{Cursor, Read, Write};
use std::{cmp, io};

use crate::constants::CapabilityFlag;
use crate::constants::{
    CHARACTER_SET_UTF8, DEFAULT_SERVER_CAPABILITY, MYSQL_NATIVE_PASSWORD,
    PROTOCOL_VERSION, SERVER_STATUS_AUTOCOMMIT,
};
use crate::errors::{ProtoError, ProtoResult};
use crate::proto::auth::ReadUntil;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use rand::Rng;

#[derive(Debug, Default)]
pub struct Greeting {
    status_flag: u16,
    capability: u32,
    connection_id: u32,
    server_version: String,
    auth_plugin_name: String,
    salt: Vec<u8>,
}

fn byte_rand(min: u64, max: u64) -> u8 {
    let mut rng = rand::thread_rng();
    (min + rng.gen_range(0, max - min)) as u8
}

impl Greeting {
    pub fn new(connection_id: u32, server_version: String) -> Box<Self> {
        let mut salt = vec![0; 20];
        for i in 0..salt.len() {
            salt[i] = byte_rand(1, 123);
        }
        box Greeting {
            status_flag: SERVER_STATUS_AUTOCOMMIT,
            capability: DEFAULT_SERVER_CAPABILITY,
            connection_id,
            server_version,
            auth_plugin_name: "".to_string(),
            salt,
        }
    }

    pub fn status_flag(&self) -> u16 {
        self.status_flag
    }

    pub fn capability(&self) -> u32 {
        self.capability
    }

    /// Initial Handshake Packet - protocol version 10
    /// See https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::HandshakeV10
    pub fn write_handshake_v10(&mut self, enable_tls: bool) -> io::Result<Vec<u8>> {
        if enable_tls {
            self.capability |= CapabilityFlag::CapabilityClientSSL as u32;
        }
        let mut buf = vec![];
        // [u8] protocol version
        buf.write_u8(PROTOCOL_VERSION)?;
        // [string] server version
        buf.write(self.server_version.as_bytes())?;
        buf.write_u8(0)?;
        // [u32] connection id
        buf.write_u32::<LittleEndian>(self.connection_id)?;
        // [string] auth-plugin-data-part-1
        buf.write(&self.salt[..8])?;
        buf.write_u8(0)?;
        // [u16] capability flags (lower 2 bytes)
        buf.write_u16::<LittleEndian>(self.capability as u16)?;
        // [u8] character set
        buf.write_u8(CHARACTER_SET_UTF8)?;
        // [u16] status flags
        buf.write_u16::<LittleEndian>(self.status_flag)?;
        // [u16] capability flags (upper 2 bytes)
        buf.write_u16::<LittleEndian>((self.capability >> 16) as u16)?;
        // [u8] length of auth-plugin-data
        buf.write_u8(21u8)?;
        // [0;10] reserved (all [00])
        buf.write(&[0; 10])?;
        // auth-plugin-data-part-2 ($len=MAX(13, length of auth-plugin-data - 8))
        buf.write(&self.salt[8..])?;
        buf.write_u8(0)?;

        // string[NUL]    auth-plugin name
        buf.write(MYSQL_NATIVE_PASSWORD.as_ref())?;
        buf.write_u8(0)?;
        Ok(buf)
    }

    pub fn parse_client_handshake_packet(&mut self, payload: &[u8]) -> ProtoResult<()> {
        let mut payload = Cursor::new(payload);
        // Parse protocol version
        match payload.read_u8() {
            Err(_) => {
                return Err(ProtoError::ReadProtocolVersionError);
            }
            _ => {} // Always 10
        }
        unsafe {
            // server version
            payload
                .real_read_until(0x00, self.server_version.as_mut_vec())
                .map_err(|_| ProtoError::ReadServerVersionError)?;
            // connection_id
            self.connection_id = payload
                .read_u32::<LittleEndian>()
                .map_err(|_| ProtoError::ReadConnectionIdError)?;
            let mut salt1 = vec![0; 8];
            // salt[..8]
            payload
                .read(&mut salt1)
                .map_err(|_| ProtoError::ReadSaltError)?;
            payload.read_u8().map_err(|_| ProtoError::ReadZeroError);

            // capability flags (lower 2 bytes)
            let lower_capability = payload
                .read_u16::<LittleEndian>()
                .map_err(|_| ProtoError::ReadCapabilityFlagError)?;
            // charset
            payload.read_u8().map_err(|_| ProtoError::ReadCharsetError);
            // status flag
            self.status_flag = payload
                .read_u16::<LittleEndian>()
                .map_err(|_| ProtoError::ReadStatusFlagError)?;
            // capability flags (upper 2 bytes)
            let upper_capability = payload
                .read_u16::<LittleEndian>()
                .map_err(|_| ProtoError::ReadCapabilityFlagError)?;
            self.capability =
                ((upper_capability as u32) << 16) | lower_capability as u32;
            let mut auth_plugin_part1_len = 0;
            if (self.capability & CapabilityFlag::CapabilityClientPluginAuth as u32) > 0
            {
                auth_plugin_part1_len = payload
                    .read_u8()
                    .map_err(|_| ProtoError::ReadAuthPluginLenError)?;
            } else {
                payload.read_u8().map_err(|_| ProtoError::ReadZeroError)?;
            }
            // Read 10 zeros
            let mut trailer = [0; 10];
            if payload
                .read(&mut trailer)
                .map_err(|_| ProtoError::ReadZeroError)?
                != trailer.len()
            {
                return Err(ProtoError::ReadZeroError);
            }
            // string[$len]: auth-plugin-data-part-2 ($len=MAX(13, length of auth-plugin-data - 8))
            if self.capability & CapabilityFlag::CapabilityClientSecureConnection as u32
                > 0
            {
                let mut read = auth_plugin_part1_len - 8;
                if read < 0 || read > 13 {
                    read = 13;
                }
                let mut salt2 = vec![0; read as usize];
                payload
                    .read(salt2.as_mut_slice())
                    .map_err(|_| ProtoError::ReadSaltError)?;
                if salt2[read as usize - 1] != 0 {
                    return Err(ProtoError::ReadSaltError);
                }
                salt2.remove(read as usize - 1);
                self.salt = [salt1, salt2].concat();
            }
        }
        Ok(())
    }
}

impl cmp::PartialEq for Greeting {
    fn eq(&self, other: &Self) -> bool {
        self.status_flag == other.status_flag
            && self.capability == other.capability
            && self.connection_id == other.connection_id
            && self.server_version == other.server_version
            && self.auth_plugin_name == other.auth_plugin_name
            && self.salt == other.salt
    }
}

#[cfg(test)]
mod tests {
    use crate::constants::CapabilityFlag::CapabilityClientPluginAuth;
    use crate::constants::{DEFAULT_SERVER_CAPABILITY, MYSQL_NATIVE_PASSWORD};
    use crate::proto::Greeting;

    #[test]
    fn test_greeting1() {
        let mut expected = Greeting::new(4, "".to_string());
        let mut actual = box Greeting::default();
        let data = expected.write_handshake_v10(false).unwrap();
        let result = actual.parse_client_handshake_packet(data.as_slice());
        assert!(result.is_ok());
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_greeting2() {
        let mut expected = box Greeting::default();
        expected.salt = vec![0; 20];
        expected.capability =
            DEFAULT_SERVER_CAPABILITY & !(CapabilityClientPluginAuth as u32);
        assert_eq!(expected.capability, 16884237);
        let mut actual = box Greeting::default();
        let data = expected.write_handshake_v10(false).unwrap();
        let result = actual.parse_client_handshake_packet(data.as_slice());
        assert!(result.is_ok());
        assert_eq!(actual, expected);
    }
}
