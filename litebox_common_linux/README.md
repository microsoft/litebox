# Common shared elements between Linux-y systems

This crate contains common elements that various parts of the shim/platform
stack might want to refer to, such as the definition of `errno`. The majority of
the code in this crate is simply to de-duplicate the code that would otherwise
need to be repeated in various platforms (or cause platforms to depend on one
another).
