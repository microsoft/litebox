use core::arch::asm;

use thiserror::Error;

mod hypercall;
#[cfg(feature = "platform_snp")]
pub mod snp;

pub trait HyperCallArgs<Other, R = ()>: From<HostRequest<Other>> {
    fn parse_alloc_result(&self, order: u64, r: R) -> Result<u64, AllocError>;
}

pub trait HyperCallInterface<InOut: HyperCallArgs<Other, R>, Other, R = ()> {
    fn request(arg: &mut InOut) -> R;
}

pub enum HostRequest<Other> {
    Alloc { order: u64 },
    Exit,
    Terminate { reason_set: u64, reason_code: u64 },
    Other(Other),
}

#[derive(Error, Debug)]
pub enum AllocError {
    #[error("Out of memory")]
    OutOfMemory,
    #[error("Invalid input")]
    InvalidInput,
    #[error("Invalid output")]
    InvalidOutput,
}

pub trait HostInterface<InOut: HyperCallArgs<Other, R>, Other = (), R: Copy = ()> {
    type HyperCallInterface: HyperCallInterface<InOut, Other, R>;

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
