#![feature(test)]
extern crate test;

use sql_protocol::Handler;

struct DB {}

impl Handler for DB {
    fn new_connection(&self) {}
    fn close_connection(&self) {}
    fn com_query(&self) {}
}

#[cfg(test)]
mod tests {
    use sql_protocol::Server;
    use crate::DB;

    #[test]
    fn test_server() {
        let mut db = Server::new(
            "127.0.0.1:9000",
        );
        //             Box::new(DB{}),
    }
}