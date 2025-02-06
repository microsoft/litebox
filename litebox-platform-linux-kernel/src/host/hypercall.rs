use core::arch::asm;

const HVCALL_VTL_CALL: u16 = 0x0011;

pub struct HyperVInterface;

impl<'a, InOut, Other> super::HyperCallInterface<'a, InOut, Other> for HyperVInterface
where
    InOut: super::HyperCallArgs<'a, Other>,
{
    /// [VTL CALL](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/vsm#vtl-call) via VMMCALL
    fn request(arg: &mut InOut) {
        unsafe {
            asm!("vmmcall",
                in("rcx") HVCALL_VTL_CALL,
                in("r14") arg as *const _ as u64,
            );
        }
    }
}
