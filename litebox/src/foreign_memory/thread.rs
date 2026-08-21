// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use vstd::prelude::*;

verus! {

pub trait HardwareThreadProvider {
    type HardwareThread;

    spec fn thread_invariant(thread: Self::HardwareThread) -> bool;

    fn with_thread<C, R>(
        &self,
        context: C,
        operation: impl FnOnce(C, &mut Self::HardwareThread) -> R,
    ) -> (result: R)
        requires
            forall|thread: &mut Self::HardwareThread|
                #![trigger operation.requires((context, thread))]
                Self::thread_invariant(*thread) ==> operation.requires((context, thread)),
            forall|thread: &mut Self::HardwareThread, result: R|
                #![trigger operation.ensures((context, thread), result)]
                Self::thread_invariant(*thread)
                    && operation.ensures((context, thread), result)
                    ==> Self::thread_invariant(*final(thread)),
        ensures
            exists|thread: &mut Self::HardwareThread|
                #![auto]
                Self::thread_invariant(*thread)
                    && operation.ensures((context, thread), result)
                    && Self::thread_invariant(*final(thread));
}

} // verus!
