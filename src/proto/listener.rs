use std::net::{TcpListener, ToSocketAddrs};
use std::{thread};
use dakv_logger::prelude::*;
use crate::proto::Connection;
use std::sync::Arc;

pub trait Handler: Send + Sync {
    // NewConnection is called when a connection is created.
    // The handler can decide to set StatusFlags that will
    // be returned by the handshake methods.
    // In particular, ServerStatusAutocommit might be set.
    fn new_connection(&self);
    // close_connection is called when a connection is closed.
    fn close_connection(&self);
    // com_query is called when a connection receives a query.
    // Note the contents of the query slice may change after
    // the first call to callback. So the Handler should not
    // hang on to the byte slice.
    fn com_query(&self);

    fn check_auth(&self) {
        self.com_query()
    }
}

pub struct Listener {
    listener: TcpListener,
    connection_id: u32,
    server_version: String,
}


impl Listener {
    pub fn new_tcp_listener<Addr: ToSocketAddrs>(addr: Addr) -> Self {
        let listener = TcpListener::bind(addr).unwrap();
        Listener {
            listener,
            connection_id: 0,
            server_version: "".to_string(),
        }
    }

    pub fn accept(&mut self, handler: Arc<dyn Handler>) {
        info!("Start server ...");
        for stream in self.listener.incoming() {
            let connection_id = self.connection_id;
            self.connection_id += 1;
            let server_version = self.server_version.clone();
            let handler = handler.clone();
            match stream {
                Ok(stream) => {
                    thread::spawn(move || {
                        let mut conn = Connection::new(connection_id, server_version);
                        conn.handle(stream, handler);
                    });
                }
                Err(_) => {}
            }
        }
    }
}

