use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

pub fn is_host_online(host: &str, port: u16) -> bool {
    let addr = format!("{}:{}", host, port);
    if let Ok(mut addrs) = addr.to_socket_addrs() {
        if let Some(socket_addr) = addrs.next() {
            return TcpStream::connect_timeout(&socket_addr, Duration::from_secs(2)).is_ok();
        }
    }
    false
}