use std::net::{TcpListener, ToSocketAddrs};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::{io, thread};

use crate::proto::Connection;
use crate::sql_type::SqlResult;

use dakv_logger::prelude::*;

pub trait Handler: Send + Sync {
    // new_connection is called when a connection is created.
    // The handler can decide to set StatusFlags that will
    // be returned by the handshake methods.
    // In particular, ServerStatusAutocommit might be set.
    fn new_connection(&self);
    // close_connection is called when a connection is closed.
    fn close_connection(&self);
    // com_query is called when a connection receives a query.
    fn com_query(
        &self,
        sql: &str,
        callback: &mut dyn FnMut(SqlResult) -> io::Result<()>,
    ) -> io::Result<()>;

    fn check_auth(&self) {}
}

pub struct Listener {
    listener: TcpListener,
    connection_id: u32,
    server_version: String,
    shutdown: AtomicBool,
}

impl Listener {
    pub fn new_tcp_listener<Addr: ToSocketAddrs>(addr: Addr) -> Self {
        let listener = TcpListener::bind(addr).unwrap();
        Listener {
            listener,
            connection_id: 0,
            server_version: "5.7.0".to_string(),
            shutdown: AtomicBool::new(false),
        }
    }

    pub fn accept(&mut self, handler: Arc<dyn Handler>) {
        debug!("Start server ...");
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
                Err(_) => {
                    error!("Empty stream");
                }
            }
        }
    }
}
