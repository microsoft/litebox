# How does LiteBox relate to the Windows operating system?

Below is a **verification-first, non-marketing explanation** of LiteBox’s relationship to Windows.

---

## High-confidence statements (well-supported by your description)

### 1. **LiteBox is not an alternative to Windows**

LiteBox does **not** replace:

* The Windows kernel (NT)
* The Win32 / Win64 subsystem
* Windows process, service, or driver models

Windows remains the **host operating system** when LiteBox runs on Windows.

---

### 2. **Windows is a “South platform” for LiteBox**

In LiteBox terms, Windows functions as a **southbound execution substrate**.

That means:

* Windows provides CPU scheduling, physical memory, hardware access
* LiteBox deliberately **refuses to inherit** the full Windows API surface
* LiteBox exposes a **much smaller, mediated contract upward**

Conceptually:

```
Application / Runtime
        ↑
   LiteBox (Library OS / Sandbox)
        ↑
   Windows NT Kernel + minimal Win32/NT calls
```

Windows is treated as **untrusted infrastructure**, not as a rich API partner.

---

### 3. **LiteBox intentionally avoids Win32 as a dependency**

A key relationship point:

* Win32 is *large*, *historical*, and *privilege-rich*
* LiteBox aims to **shrink the attack surface**
* Therefore LiteBox either:

  * Bypasses Win32 entirely
  * Or uses a very narrow, auditable subset

This mirrors how:

* WASI avoids POSIX
* Drawbridge avoided full Win32
* Modern sandboxed runtimes avoid libc syscalls

---

## Plausible / likely (but architecture-dependent)

### 4. **LiteBox may sit beside, not inside, Windows subsystems**

Depending on deployment:

* **User-mode LiteBox**

  * Runs as a normal Windows process
  * Uses NT syscalls or restricted Win32 entry points
  * Gains isolation via policy, capability mediation, and interface reduction

* **Kernel-mode LiteBox**

  * Could exist as:

    * A kernel driver
    * A hypervisor-adjacent component
  * Acts as a syscall broker or capability gatekeeper

Windows still controls privilege escalation and hardware access.

---

### 5. **LiteBox is orthogonal to Windows security models**

LiteBox does **not** replace:

* Windows ACLs
* UAC
* AppContainers
* Code signing
* Driver signing

Instead, it:

* Adds a *parallel*, tighter trust boundary
* Applies **least-authority semantics at the runtime level**
* Can constrain software even when Windows would otherwise allow it

---

## What LiteBox enables *on* Windows (practical effects)

### A. Hardened application execution

* Run untrusted or partially trusted code
* Without granting it Win32-level powers
* With deterministic, inspectable interfaces

### B. Cross-platform portability

* Same LiteBox north shim
* Different south platforms (Windows, Linux, kernel, embedded)
* Windows becomes “just another substrate”

### C. Long-term API stability

* Windows APIs evolve, deprecate, accrete risk
* LiteBox provides a **stable, minimal contract** above that churn

---

## What LiteBox does *not* try to do to Windows

| Myth                                       | Reality     |
| ------------------------------------------ | ----------- |
| “LiteBox replaces Windows security”        | ❌ No        |
| “LiteBox is a Windows compatibility layer” | ❌ No        |
| “LiteBox competes with Win32”              | ❌ No        |
| “LiteBox requires modifying Windows”       | ❌ Likely no |

LiteBox is **parasitic in the best sense**: it lives on Windows but does not entangle itself with it.

---

## One-sentence summary

> **LiteBox treats Windows as a minimal execution substrate, not a programming model—using Windows for mechanics, while deliberately avoiding its APIs to reduce attack surface and increase control.**
