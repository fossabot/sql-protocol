use byteorder::{WriteBytesExt, LittleEndian};
use std::io::{Read, Write};
use std::io;
use std::net::TcpStream;
use std::ptr;

use crate::errors::{ProtoResult, ProtoError};
use crate::constants::MAX_PACKET_SIZE;

pub struct Packets {
    sequence_id: u8,
    stream: Option<TcpStream>,
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

    pub fn read_header(&mut self) -> io::Result<usize> {
        let mut header = [0; 4];
        if let Some(inner) = &mut self.stream {
            return match inner.read_exact(&mut header) {
                Ok(n) => {
                    let sequence = header[3];
                    if sequence != self.sequence_id {
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
        }
        self.sequence_id += 1;
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
                inner.write(&header)?;

                inner.write(&data[index..index + pkg_len])?;
                self.sequence_id += 1;
                len -= pkg_len;
                if len == 0 {
                    if pkg_len == MAX_PACKET_SIZE {
                        inner.write(&[0, 0, 0, self.sequence_id])?;
                        self.sequence_id += 1;
                    }
                    return Ok(());
                }
                index += pkg_len;
            }
        }
        panic!("Invalid stream");
    }
}