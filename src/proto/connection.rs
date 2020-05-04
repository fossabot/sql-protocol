use std::net::TcpStream;
use std::sync::Arc;

use crate::errors::ProtoResult;
use crate::proto::packets::Packets;
use crate::proto::Handler;
use crate::proto::{Auth, Greeting};

use dakv_logger::prelude::*;

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
        self.auth
            .parse_client_handshake_packet(payload.unwrap().as_slice(), true)?;
        Ok(())
    }

    pub fn handle(&mut self, stream: TcpStream, handler: Arc<dyn Handler>) {
        debug!("Read request ...");

        self.packets.set_stream(Box::new(stream));
        // todo tls
        self.write_handshake_v10();
        let pkg = self.packets.read_ephemeral_packet_direct().unwrap();
        self.auth
            .parse_client_handshake_packet(pkg.as_slice(), false)
            .unwrap();
        debug!("{:?}", pkg.as_slice());
        debug!("{}", self.auth);
        // todo tls
        self.packets
            .write_ok_packet(0, 0, self.greeting.status_flag(), 0)
            .unwrap();
        loop {
            let result: ProtoResult<()> = self.packets.handle_next_command(
                handler.clone(),
                self.greeting.status_flag(),
                self.greeting.capability(),
            );
            if result.is_err() {
                return;
            }
        }
    }
    fn write_handshake_v10(&mut self) {
        let pkg = self.greeting.write_handshake_v10(false).unwrap();
        debug!("handshake:{:?}", pkg.as_slice());
        self.packets.write_packet(pkg.as_slice()).unwrap();
    }
}
