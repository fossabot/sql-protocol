use byteorder::{WriteBytesExt, LittleEndian};
use std::io;
use std::io::Write;
use crate::proto::stream::Stream;
use std::net::TcpStream;
use std::ptr;

use crate::errors::{ProtoResult, ProtoError};

pub struct Packets {
    sequence_id: u8,
    stream: *mut Stream,
}

impl Packets {
    pub fn new() -> Self {
        Packets {
            sequence_id: 0,
            stream: ptr::null_mut(),
        }
    }

    pub fn set_stream(&mut self, mut stream: TcpStream) {
        self.stream = &mut Stream::new(stream);
    }
    pub fn next(&self) -> ProtoResult<Vec<u8>> {
        let mut buf = [0; 1];
        unsafe{
            match (*self.stream).read() {
                _ => { return Err(ProtoError::ReadNextPacketError); }
//            Ok(data) => {}
            }
        }

    }

    pub fn write(&mut self, payload: &[u8]) -> io::Result<()> {
        let mut buf = vec![];
        // length of payload
        buf.write_u24::<LittleEndian>(payload.len() as u32)?;
        // sequence id
        buf.write_u8(self.sequence_id)?;
        // payload
        buf.write(payload)?;
        unsafe {
            (*self.stream).write(buf.as_slice())?;
        }
        self.sequence_id += 1;
        Ok(())
    }
}