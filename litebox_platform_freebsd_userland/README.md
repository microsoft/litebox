# A LiteBox Platform for running LiteBox on userland Linux

This crate provides an instantiation of the LiteBox `platform::Provider`, with
parameterized punchthrough.

It requires access to a TUN device that has been initialized. For convenience,
[`./scripts/tun-setup.sh`](./scripts/tun-setup.sh) will help you initialize a
TUN device and ready it for usage with for this platform. Passing `-h` as an
argument will show a help message for how to use this helper script.
