use std::sync::Arc;

use sql_protocol::{Listener, Handler};
use dakv_logger::set_logger_level;


struct Server {
    listener: Listener,
}

impl Server {
    pub fn new(addr: &str) -> Self {
        Server {
            listener: Listener::new_tcp_listener(
                addr,
            ),
        }
    }

    pub fn start(&mut self, handler: Arc<dyn Handler>) {
        self.listener.accept(handler);
    }
}


struct DB {}

impl Handler for DB {
    fn new_connection(&self) {}
    fn close_connection(&self) {}
    fn com_query(&self) {}
}

fn main() {
    let _logger = set_logger_level(true, None);
    let mut s = Server::new(
        "127.0.0.1:5000",
    );
    s.start(Arc::new(DB {}));
}
