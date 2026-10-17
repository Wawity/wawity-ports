use socket2::{Domain, Protocol, Socket, Type};
use std::{
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener},
    sync::mpsc::{self, Sender},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

pub const MAX_LEASE: Duration = Duration::from_secs(70);
const MAX_CONNECTIONS: usize = 64;

#[derive(Debug)]
pub struct Incoming {
    pub peer: SocketAddr,
    pub local: SocketAddr,
    pub at: Instant,
}

#[derive(Debug)]
pub struct Report {
    pub endpoint: SocketAddr,
    pub incoming: Vec<Incoming>,
    pub reason: String,
}

pub struct TestServer {
    pub endpoint: SocketAddr,
    stop: Sender<()>,
    worker: Option<JoinHandle<Report>>,
}

#[cfg(windows)]
fn exclusive(socket: &Socket) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    #[link(name = "ws2_32")]
    extern "system" {
        fn setsockopt(socket: usize, level: i32, name: i32, value: *const u8, len: i32) -> i32;
        fn WSAGetLastError() -> i32;
    }
    let enabled: i32 = 1;
          let result = unsafe {
        setsockopt(
            socket.as_raw_socket() as usize,
            0xffff, 
            -5,     
            &enabled as *const i32 as *const u8,
            std::mem::size_of_val(&enabled) as i32,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }))
    }
}

#[cfg(not(windows))]
fn exclusive(socket: &Socket) -> io::Result<()> {
    socket.set_reuse_address(false)
}

impl TestServer {
    pub fn start(local: Ipv4Addr, port: u16, lease: Duration) -> Result<Self, String> {
        if (cfg!(test) || std::env::var_os("WAWITY_PORTS_TEST_MODE").is_some())
            && !local.is_loopback()
        {
            return Err("Diagnostic tests may bind loopback only.".into());
        }
        if (!local.is_private() && !(cfg!(test) && local.is_loopback()))
            || port == 0 && !cfg!(test)
            || lease.is_zero()
            || lease > MAX_LEASE
        {
            return Err("Unsafe diagnostic address, port or lease; listener not started.".into());
        }
        let deadline = Instant::now() + lease;
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
            .map_err(|e| e.to_string())?;
        exclusive(&socket).map_err(|e| format!("Exclusive TCP binding unavailable: {e}"))?;
        socket
            .bind(&SocketAddrV4::new(local, port).into())
            .map_err(|e| format!("TCP bind refused; existing service left unchanged: {e}"))?;
        socket.listen(8).map_err(|e| e.to_string())?;
        socket.set_nonblocking(true).map_err(|e| e.to_string())?;
        let listener: TcpListener = socket.into();
        let endpoint = listener.local_addr().map_err(|e| e.to_string())?;
        let (stop, receiver) = mpsc::channel();
        let worker = thread::Builder::new()
            .name("diagnostic-tcp-lease".into())
            .spawn(move || {
                let mut report = Report {
                    endpoint,
                    incoming: Vec::new(),
                    reason: "hard lease expired".into(),
                };
                let mut accepted = 0;
                while Instant::now() < deadline {
                    match receiver.try_recv() {
                        Ok(()) | Err(mpsc::TryRecvError::Disconnected) => {
                            report.reason = "explicit stop".into();
                            break;
                        }
                        Err(mpsc::TryRecvError::Empty) => {}
                    }
                    match listener.accept() {
                        Ok((stream, peer)) => {
                            accepted += 1;
                            let at = Instant::now();
                            let local = stream.local_addr();
                                                       drop(stream);
                            if at >= deadline {
                                break;
                            }
                            if let Ok(local) = local {
                                report.incoming.push(Incoming { peer, local, at });
                            }
                            if accepted >= MAX_CONNECTIONS {
                                report.reason = "64 connection limit reached".into();
                                break;
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            let wait = Duration::from_millis(10)
                                .min(deadline.saturating_duration_since(Instant::now()));
                            match receiver.recv_timeout(wait) {
                                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                                    report.reason = "explicit stop".into();
                                    break;
                                }
                                Err(mpsc::RecvTimeoutError::Timeout) => {}
                            }
                        }
                        Err(e) => {
                            report.reason = format!("accept failed: {e}");
                            break;
                        }
                    }
                }
                drop(listener);
                report
            })
            .map_err(|e| e.to_string())?;
        Ok(Self {
            endpoint,
            stop,
            worker: Some(worker),
        })
    }

    pub fn stop(mut self) -> Result<Report, String> {
        let _ = self.stop.send(());
        self.worker
            .take()
            .unwrap()
            .join()
            .map_err(|_| "Diagnostic listener worker panicked; socket closed during unwind.".into())
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Read, net::TcpStream};

    #[test]
    fn loopback_records_and_sends_no_content_then_closes() {
        let server = TestServer::start(Ipv4Addr::LOCALHOST, 0, MAX_LEASE).unwrap();
        let port = server.endpoint.port();
        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut buffer = [0; 16];
        assert_eq!(client.read(&mut buffer).unwrap(), 0);
        let report = server.stop().unwrap();
        assert_eq!(report.incoming.len(), 1);
        assert!(report.incoming[0].peer.ip().is_loopback());
        assert_eq!(report.incoming[0].local, report.endpoint);
        assert!(TcpStream::connect_timeout(&report.endpoint, Duration::from_millis(100)).is_err());
    }

    #[test]
    fn busy_port_is_not_replaced_including_reuse_attempt() {
        let existing = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = existing.local_addr().unwrap().port();
        assert!(TestServer::start(Ipv4Addr::LOCALHOST, port, MAX_LEASE).is_err());
        let _client = TcpStream::connect(existing.local_addr().unwrap()).unwrap();
        existing.accept().unwrap();
        drop(existing);
        let server = TestServer::start(Ipv4Addr::LOCALHOST, 0, MAX_LEASE).unwrap();
        let port = server.endpoint.port();
        let other = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
        other.set_reuse_address(true).unwrap();
        assert!(other
            .bind(&SocketAddrV4::new(Ipv4Addr::LOCALHOST, port).into())
            .is_err());
        drop(server);
    }

    #[test]
    fn raii_cleans_up_on_error_and_unwind() {
        let mut endpoint = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0).into();
        let mut fail = || -> Result<(), String> {
            let server = TestServer::start(Ipv4Addr::LOCALHOST, 0, MAX_LEASE)?;
            endpoint = server.endpoint;
            Err("later operation failed".into())
        };
        assert!(fail().is_err());
        assert!(TcpStream::connect_timeout(&endpoint, Duration::from_millis(100)).is_err());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let server = TestServer::start(Ipv4Addr::LOCALHOST, 0, MAX_LEASE).unwrap();
            endpoint = server.endpoint;
            panic!("later operation panicked");
        }))
        .is_err());
        assert!(TcpStream::connect_timeout(&endpoint, Duration::from_millis(100)).is_err());
    }

    #[test]
    fn hard_deadline_closes_without_owner_cleanup() {
        let server = TestServer::start(Ipv4Addr::LOCALHOST, 0, Duration::from_millis(30)).unwrap();
        let port = server.endpoint.port();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !server.worker.as_ref().unwrap().is_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert!(server.worker.as_ref().unwrap().is_finished());
        assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_err());
        assert_eq!(server.stop().unwrap().reason, "hard lease expired");
        assert!(TestServer::start(Ipv4Addr::UNSPECIFIED, port, MAX_LEASE).is_err());
        assert!(TestServer::start(Ipv4Addr::LOCALHOST, port, Duration::ZERO).is_err());
        assert!(TestServer::start(
            Ipv4Addr::LOCALHOST,
            port,
            MAX_LEASE + Duration::from_nanos(1)
        )
        .is_err());
    }

    #[test]
    fn connection_limit_self_stops() {
        let server = TestServer::start(Ipv4Addr::LOCALHOST, 0, MAX_LEASE).unwrap();
        let port = server.endpoint.port();
        for _ in 0..MAX_CONNECTIONS {
            let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            assert_eq!(client.read(&mut [0]).unwrap(), 0);
        }
        let report = server.stop().unwrap();
        assert_eq!(report.incoming.len(), MAX_CONNECTIONS);
        assert_eq!(report.reason, "64 connection limit reached");
    }
}
