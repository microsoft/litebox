# LiteBox

> A security-focused library OS

LiteBox is a sandboxing library OS that drastically cuts down the interface to the host, thereby reducing attack surface. It is designed for usage in both kernel and non-kernel scenarios.

LiteBox exposes a [`nix`](https://docs.rs/nix)/[`rustix`](https://docs.rs/rustix)-like interface "above" when it is provided a `Platform` interface "below".

Example use cases include:
- VSBox, which provides a Linux ABI interface to run programs on top of SEV SNP
- WasmBox, which provides a WASI interface to run programs on unmodified Linux userland

The figure below shows roughly how LiteBox and related projects interact:

```mermaid
flowchart TD
    lp("Linux Program")
    wp("Wasm Program")
    psl["POSIX Shim Layer"]
    wsl["WASI Shim Layer"]
    rsl["Rust Shim Layer"]
    alloc{{Allocator}}
    lb["LiteBox"]
    pflk["Linux Kernel Platform"]
    pflu["Linux User Platform"]
    hssnp["SEV SNP Host"]
    hslxu["Linux User Host"]

    lp-->|POSIX interface|psl
    wp-->|WASI interface|wsl

    subgraph "&nbsp;"
        psl
    end
    subgraph "&nbsp;&nbsp;"
        wsl-->|StdProvider interface|rsl
    end

    psl & rsl-->|nix-like interface|lb
    
    subgraph "&nbsp;&nbsp;&nbsp;"
        lb
    end

    %% The `~~~` thing is purely for stylistic reasons
    alloc ~~~ lb
    lb-->alloc

    lb-->|Platform interface|pflk & pflu

    subgraph "&nbsp;&nbsp;&nbsp;&nbsp;"
        pflk
        pflu
    end

    pflk-->|Host interface|hssnp
    pflu-->|Host interface|hslxu

    subgraph "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
        hssnp
        hslxu
    end
```
