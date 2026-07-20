# A shim that provides a Linux-compatible ABI via LiteBox

This shim is generic over the choice of [LiteBox platform](../litebox/platform/index.html).
The concrete platform is chosen by the runner and threaded in when the shim is
constructed: `LinuxShimBuilder::<Platform>::new(platform)` takes a
`&'static Platform`, and the resulting `LinuxShim<Platform, FS>` (and every type
below it) carries that `Platform` type parameter. There is no global platform
accessor — nothing in the shim reaches for an ambient platform.

Any type that satisfies the `ShimPlatform` aggregate bound can be used. Runners
depend on a concrete platform crate (e.g. `litebox_platform_linux_userland`) and
pass an instance directly:

```rust,ignore
let platform = LinuxUserland::new(/* ... */); // &'static LinuxUserland
let shim = LinuxShimBuilder::new(platform).build::<MyFs>();
```
