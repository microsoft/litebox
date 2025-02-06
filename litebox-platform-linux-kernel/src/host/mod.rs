use core::arch::asm;

mod hypercall;
// #[cfg(feature = "platform_snp")]
pub mod snp;

pub trait HyperCallInterface<T> {
    fn request(arg: &mut T);
}

pub enum HostRequest<Other> {
    Exit,
    Terminate { reason_set: u64, reason_code: u64 },
    Other(Other),
}

pub trait HostInterface<T, Other = ()> {
    type HyperCallInterface: HyperCallInterface<T>;

    // construct arg of type T from HostRequest
    fn get_request(request: HostRequest<Other>) -> T;

    fn call(request: HostRequest<Other>) {
        let mut req = Self::get_request(request);
        Self::HyperCallInterface::request(&mut req);
    }

    fn exit() {
        Self::call(HostRequest::Exit);
    }

    fn terminate(reason_set: u64, reason_code: u64) -> ! {
        Self::call(HostRequest::Terminate {
            reason_set,
            reason_code,
        });

        // In case hypervisor fails to terminate it or intentionally reschedules it,
        // halt the CPU to prevent further execution
        loop {
            unsafe { asm!("hlt") }
        }
    }
}
