use super::*;
use std::io::{ErrorKind, Read, Write};

pub(super) struct Socket {
    tcp: TcpStream,
    closed: AtomicBool,
    owner: Mutex<Option<SetupClose>>,
    handshake: Mutex<Option<Instant>>,
    pub(super) lease: Mutex<Option<Arc<()>>>,
}
impl Socket {
    pub(super) fn new(tcp: TcpStream, deadline: Instant) -> Result<Arc<Self>> {
        tcp.set_nonblocking(true).map_err(|_| Invalid)?;
        Ok(Arc::new(Self {
            tcp,
            closed: AtomicBool::new(false),
            owner: Mutex::new(None),
            handshake: Mutex::new(Some(deadline)),
            lease: Mutex::new(None),
        }))
    }
    pub(super) fn close(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            // Shut down writes first: on some platforms a peer half-close
            // makes SHUT_RDWR fail before the write half is shut down.
            let _ = self.tcp.shutdown(Shutdown::Write);
            let _ = self.tcp.shutdown(Shutdown::Read);
        }
        let owner = self.owner.lock().unwrap_or_else(|p| p.into_inner()).clone();
        if let Some(owner) = owner {
            owner.close();
        }
    }
    pub(super) fn live(&self) -> bool {
        !self.closed.load(Ordering::Acquire)
            && self
                .handshake
                .lock()
                .is_ok_and(|d| d.is_none_or(|end| Instant::now() < end))
            && self
                .owner
                .lock()
                .is_ok_and(|o| o.as_ref().is_none_or(|owner| !owner.closed()))
    }
    pub(super) fn bind(&self, owner: SetupClose) -> Result<()> {
        {
            let mut bound = self.owner.lock().map_err(|_| Invalid)?;
            ensure(bound.is_none())?;
            *bound = Some(owner);
        }
        if !self.live() {
            self.close();
            return Err(Invalid);
        }
        Ok(())
    }
    pub(super) fn ready(&self) -> Result<()> {
        let mut deadline = self.handshake.lock().map_err(|_| Invalid)?;
        ensure(
            !self.closed.load(Ordering::Acquire)
                && deadline.is_some_and(|end| Instant::now() < end),
        )?;
        *deadline = None;
        Ok(())
    }
    fn matches(&self, close: &SetupClose) -> bool {
        self.owner
            .lock()
            .is_ok_and(|owner| owner.as_ref().is_some_and(|old| old.same_owner(close)))
    }
}
impl Drop for Socket {
    fn drop(&mut self) {
        self.close();
    }
}
pub(super) struct Stream {
    pub(super) socket: Arc<Socket>,
    pub(super) pool: Arc<Pool>,
    bound: Duration,
}
struct Budget {
    end: Instant,
    mono: Option<i64>,
}
impl Stream {
    pub(super) fn bound_ms(&self) -> i64 {
        self.bound.as_millis().max(1) as i64
    }
    pub(super) fn new(socket: Arc<Socket>, pool: Arc<Pool>, bound: Duration) -> Self {
        Self {
            socket,
            pool,
            bound,
        }
    }
    fn check(&self, budget: &Budget) -> Result<()> {
        ensure(self.socket.live() && self.pool.live() && Instant::now() < budget.end)?;
        let now = self.pool.sample()?;
        ensure(budget.mono.is_none_or(|end| now.mono_ms < end))
    }
    fn begin(&self, mono: Option<i64>) -> Result<Budget> {
        let budget = Budget {
            end: Instant::now().checked_add(self.bound).ok_or(Invalid)?,
            mono,
        };
        self.check(&budget)?;
        Ok(budget)
    }
    fn read_exact(&self, mut bytes: &mut [u8], budget: &Budget) -> Result<()> {
        while !bytes.is_empty() {
            self.check(budget)?;
            match (&self.socket.tcp).read(bytes) {
                Ok(0) => return Err(Invalid),
                Ok(n) => {
                    bytes = &mut bytes[n..];
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => self.pool.pause(),
                Err(error) if error.kind() == ErrorKind::Interrupted => (),
                Err(_) => return Err(Invalid),
            }
        }
        self.check(budget)
    }
    pub(super) fn receive_frame(&mut self, mono: Option<i64>) -> Result<Vec<u8>> {
        let result = (|| {
            let budget = self.begin(mono)?;
            let mut header = [0; 4];
            self.read_exact(&mut header, &budget)?;
            let n = frame_length(header)?;
            let mut wire = vec![0; n];
            self.read_exact(&mut wire, &budget)?;
            Ok(wire)
        })();
        if result.is_err() {
            self.socket.close();
        }
        result
    }
    pub(super) fn send_frame(&mut self, wire: &[u8], mono: Option<i64>) -> Result<()> {
        let result = (|| {
            ensure((1..=32768).contains(&wire.len()))?;
            let budget = self.begin(mono)?;
            let header = (wire.len() as u32).to_be_bytes();
            for mut bytes in [header.as_slice(), wire] {
                while !bytes.is_empty() {
                    self.check(&budget)?;
                    match (&self.socket.tcp).write(bytes) {
                        Ok(0) => return Err(Invalid),
                        Ok(n) => bytes = &bytes[n..],
                        Err(error) if error.kind() == ErrorKind::WouldBlock => self.pool.pause(),
                        Err(error) if error.kind() == ErrorKind::Interrupted => (),
                        Err(_) => return Err(Invalid),
                    }
                }
            }
            self.check(&budget)
        })();
        if result.is_err() {
            self.socket.close();
        }
        result
    }
}
impl SetupIO for Stream {
    fn send(&mut self, wire: &[u8], deadline_ms: i64, close: &SetupClose) -> Result<()> {
        if !self.socket.matches(close) {
            self.socket.close();
            return Err(Invalid);
        }
        self.send_frame(wire, Some(deadline_ms))
    }
    fn receive(&mut self, deadline_ms: i64, close: &SetupClose) -> Result<Vec<u8>> {
        if !self.socket.matches(close) {
            self.socket.close();
            return Err(Invalid);
        }
        self.receive_frame(Some(deadline_ms))
    }
}
impl Drop for Stream {
    fn drop(&mut self) {
        self.socket.close();
    }
}

fn frame_length(header: [u8; 4]) -> Result<usize> {
    let n = u32::from_be_bytes(header) as usize;
    ensure((1..=32768).contains(&n))?;
    Ok(n)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frame_length_is_bounded_before_allocation() {
        for n in [1u32, 32768] {
            assert_eq!(frame_length(n.to_be_bytes()).unwrap(), n as usize);
        }
        for n in [0u32, 32769, u32::MAX] {
            assert!(frame_length(n.to_be_bytes()).is_err());
        }
    }
}
