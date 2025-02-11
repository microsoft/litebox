use litebox::platform::{Punchthrough, PunchthroughToken};

use crate::error;

pub mod hypercall;
pub mod linux;
#[cfg(feature = "platform_snp")]
pub mod snp;

/// Interface for hypercalls (See [`hypercall::HyperVInterface`] for example)
pub trait HyperCallInterface<InOut, R = ()> {
    fn request(arg: &mut InOut) -> R;
}

/// Common punchthrough requests
/// `Other` is for additional punchthrough requests (See [`snp::SnpPunchthrough`] for example)
pub enum HostPunchthrough<'a, Other> {
    /// Allocate pages ((2 ^ order) * PAGE_SIZE)
    Alloc {
        order: u64,
    },
    RecvPacket(&'a mut [u8]),
    SendPacket(&'a [u8]),
    Exit,
    Terminate {
        reason_set: u64,
        reason_code: u64,
    },
    Other(Other),
}

impl<Other> Punchthrough for HostPunchthrough<'_, Other> {
    type ReturnSuccess = u64;
    type ReturnFailure = error::Errno;
}

/// A wrapper for PunchthroughToken that has lifetime
pub trait HostPunchthroughToken<'a, InOut>
where
    Self: PunchthroughToken,
{
    type HyperCallInterface: HyperCallInterface<InOut>;
}

/// Interface for punchthrough requests
pub trait HostPunchthroughProvider<'a, InOut, Other> {
    type Token: HostPunchthroughToken<'a, InOut>;

    fn get_punchthrough_token_for(
        &mut self,
        punchthrough: HostPunchthrough<'a, Other>,
    ) -> Option<Self::Token>;

    fn alloc(&mut self, order: u64) -> Option<Self::Token> {
        let req = HostPunchthrough::Alloc { order };
        self.get_punchthrough_token_for(req)
    }

    fn recv_packet(&mut self, packet: &'a mut [u8]) -> Option<Self::Token> {
        let req = HostPunchthrough::RecvPacket(packet);
        self.get_punchthrough_token_for(req)
    }

    fn send_packet(&mut self, packet: &'a [u8]) -> Option<Self::Token> {
        let req = HostPunchthrough::SendPacket(packet);
        self.get_punchthrough_token_for(req)
    }

    // Exit allows to come back.
    // Depending on the context, it either returns back to the caller
    // or handle some requests from host
    fn exit(&mut self) -> Option<Self::Token> {
        self.get_punchthrough_token_for(HostPunchthrough::Exit)
    }

    fn terminate(&mut self, reason_set: u64, reason_code: u64) -> Option<Self::Token> {
        self.get_punchthrough_token_for(HostPunchthrough::Terminate {
            reason_set,
            reason_code,
        })
    }
}
