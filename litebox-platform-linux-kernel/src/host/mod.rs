use core::arch::asm;

use thiserror::Error;

mod hypercall;
pub mod linux;
#[cfg(feature = "platform_snp")]
pub mod snp;

pub trait HyperCallArgs<'a, Other, R = ()>: From<HostRequest<'a, Other>> {
    fn parse_alloc_result(&self, order: u64, r: R) -> Result<u64, AllocError>;

    fn parse_recv_result(&self, r: R) -> Result<usize, NetworkError>;

    fn parse_send_result(&self, r: R) -> Result<usize, NetworkError>;
}

pub trait HyperCallInterface<'a, InOut: HyperCallArgs<'a, Other, R>, Other, R = ()> {
    fn request(arg: &mut InOut) -> R;
}

pub enum HostRequest<'a, Other> {
    Alloc { order: u64 },
    RecvPacket(&'a mut [u8]),
    SendPacket(&'a [u8]),
    Exit,
    Terminate { reason_set: u64, reason_code: u64 },
    Other(Other),
}

#[derive(Error, Debug)]
pub enum AllocError {
    #[error("Out of memory")]
    OutOfMemory,
    #[error("Invalid input {0}")]
    InvalidInput(u64),
    #[error("Invalid output {0}")]
    InvalidOutput(u64),
}

#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("Would block")]
    WouldBlock,
    #[error("Interrupted")]
    Interrupted,
}

pub trait HostInterface<'a, InOut: HyperCallArgs<'a, Other, R>, Other = (), R: Copy = ()> {
    type HyperCallInterface: HyperCallInterface<'a, InOut, Other, R>;

    fn call(req: &mut InOut) -> R {
        let r = Self::HyperCallInterface::request(req);
        Self::post_check(req, r);
        r
    }

    fn post_check(_req: &InOut, _res: R) {}

    fn alloc(order: u64) -> Result<u64, AllocError> {
        let req = &mut HostRequest::Alloc { order }.into();
        let r = Self::call(req);
        req.parse_alloc_result(order, r)
    }

    fn recv_packet(packet: &'a mut [u8]) -> Result<usize, NetworkError> {
        let req = &mut HostRequest::RecvPacket(packet).into();
        let r = Self::call(req);
        req.parse_recv_result(r)
    }

    fn send_packet(packet: &'a [u8]) -> Result<usize, NetworkError> {
        if packet.is_empty() {
            return Ok(0);
        }

        let req = &mut HostRequest::SendPacket(packet).into();
        let r = Self::call(req);
        req.parse_send_result(r)
    }

    fn exit() {
        Self::call(&mut HostRequest::Exit.into());
    }

    fn terminate(reason_set: u64, reason_code: u64) -> ! {
        Self::call(
            &mut HostRequest::Terminate {
                reason_set,
                reason_code,
            }
            .into(),
        );

        // In case hypervisor fails to terminate it or intentionally reschedules it,
        // halt the CPU to prevent further execution
        loop {
            unsafe { asm!("hlt") }
        }
    }
}
