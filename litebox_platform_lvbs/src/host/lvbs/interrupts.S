/* Copyright (c) Microsoft Corporation.
   Licensed under the MIT license. */

.code64
.text

/* A user-mode STIMER expiry goes to exception_callback; a kernel-mode
 * expiry uses the LVBS rearm policy. The vector is supplied from Rust.
 */
isr_no_err_code isr_stimer stimer_handler_impl {stimer_vector}

/* Hyper-V SINT for VTL0 security violations. No register changes or EOI:
 * the VTL switch loop will inspect the message after the immediate return.
 * VTL1 and VTL0 do not execute concurrently on this VP.
 */
.global isr_hyperv_sint
isr_hyperv_sint:
    iretq

/* APIC spurious interrupt: no work and no in-service bit, hence no EOI. */
.global isr_spurious
isr_spurious:
    iretq
