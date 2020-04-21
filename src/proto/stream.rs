use std::net::TcpStream;
use std::io;

pub struct Stream {
    reader: Box<dyn io::Read>
}

impl Stream {
    pub fn new(mut stream: TcpStream) -> Self {
        Stream {
            reader: box stream
        }
    }

    pub fn write(&mut self, payload: &[u8]) -> io::Result<()>{
        Ok(())
    }

    pub fn read(&mut self) -> io::Result<()>{
        Ok(())
    }
}