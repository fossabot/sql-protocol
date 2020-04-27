use byteorder::{WriteBytesExt, LittleEndian, ReadBytesExt};
use std::io::{Read, Write};
use std::io;
use std::net::TcpStream;
use std::ptr;

use dakv_logger::prelude::*;

use crate::errors::{ProtoResult, ProtoError};
use crate::constants::{MAX_PACKET_SIZE, OK_PACKET, PacketType, CapabilityFlag, ERR_PACKET, StateError, ServerError, SERVER_MORE_RESULTS_EXISTS, EOF_PACKET};
use std::sync::Arc;
use crate::Handler;

pub struct Packets {
    sequence_id: u8,
    stream: Option<TcpStream>,
}

trait WriteLenEncode: WriteBytesExt {
    fn write_len_encode(&mut self, value: u64) -> io::Result<()>;
}

impl WriteLenEncode for TcpStream {
    fn write_len_encode(&mut self, value: u64) -> io::Result<()> {
        match value {
            value if value < 251 => {
                self.write_u8(value as u8)?;
            }
            value if value >= 251 && value < (1 << 16) => {
                self.write_u8(0xfc)?;
                self.write_u16::<LittleEndian>(value as u16)?;
            }
            value if value >= (1 << 16) && value < (1 << 24) => {
                self.write_u8(0xfd)?;
                self.write_u24::<LittleEndian>(value as u32)?;
            }
            _ => {
                self.write_u8(0xfe)?;
                self.write_u64::<LittleEndian>(value)?;
            }
        }
        Ok(())
    }
}

impl Packets {
    pub fn new() -> Self {
        Packets {
            sequence_id: 0,
            stream: None,
        }
    }

    pub fn set_stream(&mut self, mut stream: TcpStream) {
        self.stream = Some(stream);
    }

    pub fn next(&self) -> ProtoResult<Vec<u8>> {
        let mut buf = [0; 1];
        Ok(vec![])
    }

    pub fn read_ephemeral_packet_direct(&mut self) -> ProtoResult<Vec<u8>> {
        let length = self.read_header().unwrap();
        return match length {
            0 => {
                Err(ProtoError::EmptyPacketError)
            }
            l if l > MAX_PACKET_SIZE => {
                Err(ProtoError::MultiPacketNotSupport)
            }
            _ => {
                let mut c = vec![0; length];
                self.read_content(length, c.as_mut_slice()).unwrap();
                Ok(c)
            }
        };
    }

    pub fn read_ephemeral_packet(&mut self) -> ProtoResult<Vec<u8>> {
        let length = self.read_header().unwrap();
        return match length {
            0 => {
                info!("Bad packet length");
                Ok(vec![])
            }
            l if l > MAX_PACKET_SIZE => {
                let mut c = vec![0; length];
                self.read_content(length, c.as_mut_slice())?;
                loop {
                    let next = self.read_one_packet()?;
                }
                Ok(c)
            }
            _ => {
                let mut c = vec![0; length];
                self.read_content(length, c.as_mut_slice())?;
                Ok(c)
            }
        };
    }

    pub fn read_header(&mut self) -> io::Result<usize> {
        let mut header = [0; 4];
        if let Some(inner) = &mut self.stream {
            return match inner.read_exact(&mut header) {
                Ok(n) => {
                    info!("{:?}", header);
                    let sequence = header[3];
                    if sequence != self.sequence_id {
                        error!("current sequence:{}, get sequence:{}", self.sequence_id, sequence);
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid sequence"));
                    }
                    self.sequence_id += 1;
                    Ok((header[0] as usize) | (header[1] as usize) << 8 | (header[2] as usize) << 16)
                }
                _ => {
                    Err(io::Error::new(io::ErrorKind::InvalidData, "Read header failed"))
                }
            };
        }
        panic!("Stream is empty");
    }

    pub fn read_one_packet(&mut self) -> io::Result<Vec<u8>> {
        let length = self.read_header()?;
        return match length {
            0 => { Ok(vec![]) }
            _ => {
                let mut data = vec![0; length];
                self.read_content(length, data.as_mut_slice())?;
                Ok(data)
            }
        };
    }

    pub fn read_content(&mut self, len: usize, data: &mut [u8]) -> io::Result<()> {
        if let Some(inner) = &mut self.stream {
            inner.take(len as u64)
                .read(data)?;
        }
        Ok(())
    }

    pub fn write(&mut self, payload: &[u8]) -> io::Result<()> {
        let mut buf = vec![];
        // length of payload
        buf.write_u24::<LittleEndian>(payload.len() as u32)?;
        // sequence id
        buf.write_u8(self.sequence_id)?;
        // payload
        buf.write(payload)?;
        if let Some(inner) = &mut self.stream {
            inner.write(buf.as_slice())?;
        } else {
            panic!("Stream is empty");
        }
        self.sequence_id += 1;
        Ok(())
    }

    pub fn write_rows(&mut self) {}

    pub fn write_row(&mut self) {}

    pub fn write_err_packet_from_err(&mut self) -> io::Result<()> {
        self.write_err_packet(ServerError::ERUnknownError as u16, StateError::SSUnknownSQLState.into(), "Unknown error".to_string())
    }

    pub fn write_end_result(&mut self, more: bool, capability: u32, affected_rows: u64, last_insert_id: u64, flags: u16, warnings: u16) -> io::Result<()> {
        let mut flags = flags;
        if more {
            flags |= SERVER_MORE_RESULTS_EXISTS;
        }
        if capability & CapabilityFlag::CapabilityClientDeprecateEOF as u32 == 0 {
            self.write_eof_packet(flags, warnings)?;
        }
        Ok(())
    }

    pub fn write_eof_packet(&mut self, flags: u16, warnings: u16) -> io::Result<()> {
        let inner: &mut TcpStream = self.stream.as_mut().unwrap();
        inner.write_u8(EOF_PACKET)?;
        inner.write_u16::<LittleEndian>(warnings)?;
        inner.write_u16::<LittleEndian>(flags)?;
        Ok(())
    }

    pub fn write_err_packet(&mut self, err_code: u16, mut sql_state: String, err_msg: String) -> io::Result<()> {
        assert_eq!(sql_state.len(), 5);
        if let Some(inner) = &mut self.stream {
            inner.write_u8(ERR_PACKET)?;
            inner.write_u16::<LittleEndian>(err_code)?;
            inner.write_u8('#' as u8)?;
            if sql_state.is_empty() {
                sql_state = StateError::SSUnknownSQLState.into();
            }
            self.write(sql_state.as_bytes())?;
            self.write(err_msg.as_bytes())?;
            return Ok(());
        }
        panic!("Stream is empty");
    }

    pub fn write_ok_packet(&mut self, affected_rows: u64, last_insert_id: u64, flags: u16, warnings: u16) -> io::Result<()> {
        if let Some(inner) = &mut self.stream {
            inner.write_u8(OK_PACKET)?;
            // Affected rows
            inner.write_len_encode(affected_rows)?;
            // Last insert id
            inner.write_len_encode(last_insert_id)?;

            inner.write_u16::<LittleEndian>(flags)?;
            inner.write_u16::<LittleEndian>(warnings)?;
        } else {
            panic!("Stream is empty");
        }
        Ok(())
    }

    pub fn write_packet(&mut self, data: &[u8]) -> io::Result<()> {
        let mut len = data.len();
        let mut index = 0;
        if let Some(inner) = &mut self.stream {
            loop {
                let mut pkg_len = len;
                if pkg_len > MAX_PACKET_SIZE {
                    pkg_len = MAX_PACKET_SIZE;
                }

                let mut header = [0; 4];
                header[0] = pkg_len as u8;
                header[1] = (pkg_len >> 8) as u8;
                header[2] = (pkg_len >> 16) as u8;
                header[3] = self.sequence_id;
                let n = inner.write(&header)?;

                let n = inner.write(&data[index..index + pkg_len])?;
                self.sequence_id += 1;
                len -= pkg_len;
                if len == 0 {
                    if pkg_len == MAX_PACKET_SIZE {
                        let n = inner.write(&[0, 0, 0, self.sequence_id])?;
                        self.sequence_id += 1;
                    }
                    return Ok(());
                }
                index += pkg_len;
            }
        }
        panic!("Invalid stream");
    }


    pub fn handle_next_command(&mut self, handler: Arc<dyn Handler>, status: u16, capability: u32) -> ProtoResult<()> {
        self.sequence_id = 0;
        let data: Vec<u8> = self.read_ephemeral_packet().unwrap();
        let data = data.as_slice();

        info!("Packet type {}", PacketType::from(data[0]).to_string());

        match data[0].into() {
            PacketType::ComQuit => {
                info!("ComQuit");
                return Err(ProtoError::ComQuit);
            }
            PacketType::ComInitDb => {
                let db = parse_com_init_db(data);
                info!("ComInitDb {}", db);
                self.write_ok_packet(0, 0, status, 0)?;
            }
            PacketType::ComPing => {}
            PacketType::ComQuery => {
                let query = parse_com_query(data);
                let statements = if capability & CapabilityFlag::CapabilityClientMultiStatements as u32 != 0 {
                    // todo multi statements
                    vec![query]
                } else {
                    vec![query]
                };
                let length = statements.len();
                info!("Queries:{:?}", statements);
                for (index, sql) in statements.iter().enumerate() {
                    let mut more = false;
                    if index != length - 1 {
                        more = true;
                    }
                    self.exec_query(handler.clone(), sql, more)?;
                }
            }
            PacketType::ComStmtPrepare => {}
            PacketType::ComStmtExecute => {}
            PacketType::ComStmtReset => {}
            PacketType::ComStmtClose => {}
            _ => {
                let cmd: PacketType = data[0].into();
                let cmd_str: &'static str = cmd.into();
                error!("Unknown command {}", cmd_str);
//                self.write_err_packet();
            }
        }
        Ok(())
    }

    pub fn exec_query(&mut self, handler: Arc<dyn Handler>, sql: &String, more: bool) -> ProtoResult<()> {
        let result = handler.com_query();
        self.write_err_packet_from_err()?;
        Err(ProtoError::ParseComStatementError)
    }
}


fn parse_com_init_db(data: &[u8]) -> String {
    trim_packet_type(data)
}

fn parse_com_query(data: &[u8]) -> String {
    trim_packet_type(data)
}

fn trim_packet_type(data: &[u8]) -> String {
    let tmp = data[1..].to_vec();
    String::from_utf8(tmp).unwrap()
}

fn parse_com_statement(data: &[u8]) -> ProtoResult<()> {
    let mut data = &data[1..];
    let stmt_id = data.read_u32::<LittleEndian>()
        .map_err(|_| { ProtoError::ParseComStatementError });
    Ok(())
}
