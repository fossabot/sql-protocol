use std::net::TcpStream;
use std::sync::Arc;
use std::io::{Write, Read};
use std::io;

use crate::proto::{Greeting, Auth};
use crate::proto::Handler;
use crate::constants::PacketType;
use crate::errors::{ProtoError, ProtoResult};

use dakv_logger::prelude::*;
use byteorder::{ReadBytesExt, LittleEndian};
use crate::proto::packets::Packets;


pub struct Connection {
    id: u32,
    // User is the name used by the client to connect.
    // It is set during the initial handshake.
    user: String,
    greeting: Box<Greeting>,
    auth: Auth,
    packets: Packets,
}

impl Connection {
    pub fn new(id: u32, server_version: String) -> Self {
        Connection {
            id,
            user: "".to_string(),
            greeting: Greeting::new(id, server_version),
            auth: Auth::new(),
            packets: Packets::new(),
        }
    }

    pub fn check_auth(&mut self, payload: &[u8]) -> ProtoResult<()> {
        self.auth.parse_client_handshake_packet(payload, true)
    }

    pub fn unpack_auth(&mut self) -> ProtoResult<()> {
        let payload = self.packets.next();
        self.auth.parse_client_handshake_packet(payload.unwrap().as_slice(), true)?;
        Ok(())
    }

    pub fn handle(&mut self, mut stream: TcpStream, handler: Arc<dyn Handler>) {
        info!("Read request ...");

        self.packets.set_stream(stream);
        let mut buf = [0u8; 8192];
        let data = &[0u8; 1];
        // todo tls
        self.write_handshake_v10();
        let pkg = self.packets.read_ephemeral_packet_direct().unwrap();
        self.auth.parse_client_handshake_packet(pkg.as_slice(), false);
        // todo tls
        self.packets.write_ok_packet(0, 0, self.greeting.status_flag(), 0);
        info!("{:?}", pkg.as_slice());
        info!("{}", self.auth);
        loop {
            let result: ProtoResult<()> = self.packets.handle_next_command(self.greeting.status_flag());
            if result.is_err() {
                panic!("");// todo
            }
        }
    }
    fn write_handshake_v10(&mut self) {
        let pkg = self.greeting.write_handshake_v10(false).unwrap();
        self.packets.write_packet(pkg.as_slice());
        info!("write handshake");
    }


    fn write_err_packet(&self) {}
}


fn read_header_from(mut reader: Box<dyn Read>) -> io::Result<u64> {
    let mut header = [0; 4];
    let _ = reader.read(&mut header)?;
    Ok(0)
//    match result { }
}