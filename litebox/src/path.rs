// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! File-system paths

use core::ffi::CStr;

use alloc::{borrow::Cow, ffi::CString, string::String};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConversionError {
    #[error("failed to convert to {0}")]
    FailedToConvertTo(&'static str),
}

type Result<T> = core::result::Result<T, ConversionError>;

/// A private module, to help support writing sealed traits. This module should _itself_ never be
/// made public.
mod private {
    /// A trait to help seal the main `Arg` trait.
    ///
    /// This trait is explicitly public, but unnameable, thereby preventing code outside this crate
    /// from implementing this trait.
    pub trait Sealed {}

    impl Sealed for str {}
    impl Sealed for alloc::string::String {}
    impl Sealed for core::ffi::CStr {}
    impl Sealed for alloc::ffi::CString {}
    impl Sealed for alloc::borrow::Cow<'_, str> {}
    impl Sealed for alloc::borrow::Cow<'_, core::ffi::CStr> {}
    impl<T: Sealed + ?Sized> Sealed for &T {}
}

/// Trait for passing path arguments
pub trait Arg: private::Sealed {
    /// Convert to a null-terminated string
    ///
    /// If the contents are a valid C string, returns a borrowed string (cheap), otherwise returns a
    /// copied owned string (costs roughly a memcpy).
    fn to_c_str(&self) -> Result<Cow<'_, CStr>>;

    /// Convert to a Rust string
    fn as_rust_str(&self) -> Result<&str>;

    /// Lossily convert to a Rust string
    ///
    // If the contents are a valid UTF-8 string, returns a borrowed string (cheap), otherwise
    // returns a copied owned string (costs roughly a memcpy).
    fn to_rust_str_lossy(&self) -> Cow<'_, str>;

    /// Separate the path into components
    ///
    /// This simply splits the path into components. Thus each component is guaranteed to not have a
    /// `/` anymore. This does not perform any normalization, thus getting the components of
    /// `foo/../bar` would give `foo`, `..`, and `bar`.
    fn components(&self) -> Result<impl Iterator<Item = &str>> {
        Ok(self.as_rust_str()?.split('/'))
    }

    /// Normalize the path and separate into components
    ///
    /// This is similar to [`Self::components`] except with normalization. Look at the tests for
    /// details on normalization.
    fn normalized_components(&self) -> Result<impl Iterator<Item = &str>> {
        let mut parent_count = 0;
        let mut rev_norm_components = self
            .as_rust_str()?
            .rsplit('/')
            .filter(|&component| match component {
                "" | "." => false,
                ".." => {
                    parent_count += 1;
                    false
                }
                _ if parent_count > 0 => {
                    parent_count -= 1;
                    false
                }
                _ => true,
            })
            .collect::<alloc::vec::Vec<_>>();
        rev_norm_components.extend(core::iter::repeat_n("..", parent_count));
        if self.as_rust_str()?.starts_with('/') {
            rev_norm_components.push("");
        }
        Ok(rev_norm_components.into_iter().rev())
    }

    /// Convenience wrapper around [`Self::normalized_components`]
    fn normalized(&self) -> Result<String> {
        let mut res = alloc::vec![];
        res.extend(self.normalized_components()?);
        Ok(res.join("/"))
    }

    /// Convenience wrapper for getting the list of ancestors of the path.
    ///
    /// Note that this is the opposite order from Rust's `std::path::Path::ancestors`.
    ///
    /// This handles both relative and absolute paths:
    /// ```
    /// # use litebox::path::Arg as _;
    /// assert_eq!("a/../b".increasing_ancestors().unwrap().collect::<Vec<_>>(),
    ///            vec!["", "a", "a/..", "a/../b"]);
    /// assert_eq!("/a/../b".increasing_ancestors().unwrap().collect::<Vec<_>>(),
    ///            vec!["/", "/a", "/a/..", "/a/../b"]);
    /// ```
    fn increasing_ancestors(&self) -> Result<impl Iterator<Item = &str>> {
        let orig_path = self.as_rust_str()?;
        let mut path = orig_path;
        let mut res: alloc::vec::Vec<&str> = alloc::vec::Vec::new();

        if path.is_empty() {
            res.push("");
            return Ok(res.into_iter());
        }

        while !path.is_empty() {
            res.push(path);
            if let Some(posn) = path.rfind('/') {
                path = &path[..posn];
            } else {
                res.push("");
                break;
            }
        }

        if res.last().unwrap().len() > 1 {
            res.push("/");
        }

        res.reverse();

        Ok(res.into_iter())
    }
}

impl<T: Arg + ?Sized> Arg for &T {
    fn to_c_str(&self) -> Result<Cow<'_, CStr>> {
        T::to_c_str(self)
    }

    fn as_rust_str(&self) -> Result<&str> {
        T::as_rust_str(self)
    }

    fn to_rust_str_lossy(&self) -> Cow<'_, str> {
        T::to_rust_str_lossy(self)
    }

    fn components(&self) -> Result<impl Iterator<Item = &str>> {
        T::components(self)
    }

    fn normalized_components(&self) -> Result<impl Iterator<Item = &str>> {
        T::normalized_components(self)
    }

    fn normalized(&self) -> Result<String> {
        T::normalized(self)
    }

    fn increasing_ancestors(&self) -> Result<impl Iterator<Item = &str>> {
        T::increasing_ancestors(self)
    }
}

impl Arg for str {
    fn to_c_str(&self) -> Result<Cow<'_, CStr>> {
        CString::new(self.as_bytes())
            .map(Cow::Owned)
            .or(Err(ConversionError::FailedToConvertTo("c string")))
    }

    fn as_rust_str(&self) -> Result<&str> {
        Ok(self)
    }

    fn to_rust_str_lossy(&self) -> Cow<'_, str> {
        Cow::Borrowed(self)
    }
}

impl Arg for String {
    fn to_c_str(&self) -> Result<Cow<'_, CStr>> {
        CString::new(self.as_bytes())
            .map(Cow::Owned)
            .or(Err(ConversionError::FailedToConvertTo("c string")))
    }

    fn as_rust_str(&self) -> Result<&str> {
        Ok(self)
    }

    fn to_rust_str_lossy(&self) -> Cow<'_, str> {
        Cow::Borrowed(self)
    }
}

impl Arg for CStr {
    fn to_c_str(&self) -> Result<Cow<'_, CStr>> {
        Ok(Cow::Borrowed(self))
    }

    fn as_rust_str(&self) -> Result<&str> {
        self.to_str()
            .or(Err(ConversionError::FailedToConvertTo("rust string")))
    }

    fn to_rust_str_lossy(&self) -> Cow<'_, str> {
        self.to_string_lossy()
    }
}

impl Arg for CString {
    fn to_c_str(&self) -> Result<Cow<'_, CStr>> {
        Ok(Cow::Borrowed(self))
    }

    fn as_rust_str(&self) -> Result<&str> {
        self.to_str()
            .or(Err(ConversionError::FailedToConvertTo("rust string")))
    }

    fn to_rust_str_lossy(&self) -> Cow<'_, str> {
        self.to_string_lossy()
    }
}

impl Arg for Cow<'_, str> {
    fn to_c_str(&self) -> Result<Cow<'_, CStr>> {
        match self {
            Cow::Borrowed(s) => s.to_c_str(),
            Cow::Owned(s) => s.to_c_str(),
        }
    }
    fn as_rust_str(&self) -> Result<&str> {
        match self {
            Cow::Borrowed(s) => s.as_rust_str(),
            Cow::Owned(s) => s.as_rust_str(),
        }
    }
    fn to_rust_str_lossy(&self) -> Cow<'_, str> {
        match self {
            Cow::Borrowed(s) => s.to_rust_str_lossy(),
            Cow::Owned(s) => s.to_rust_str_lossy(),
        }
    }
}

impl Arg for Cow<'_, CStr> {
    fn to_c_str(&self) -> Result<Cow<'_, CStr>> {
        match self {
            Cow::Borrowed(s) => s.to_c_str(),
            Cow::Owned(s) => s.to_c_str(),
        }
    }
    fn as_rust_str(&self) -> Result<&str> {
        match self {
            Cow::Borrowed(s) => s.as_rust_str(),
            Cow::Owned(s) => s.as_rust_str(),
        }
    }
    fn to_rust_str_lossy(&self) -> Cow<'_, str> {
        match self {
            Cow::Borrowed(s) => s.to_rust_str_lossy(),
            Cow::Owned(s) => s.to_rust_str_lossy(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::path::Arg;
    use alloc::vec;
    use alloc::vec::Vec;

    #[test]
    fn path_normalization() {
        assert_eq!(
            "../foo/../bar/./baz"
                .normalized_components()
                .unwrap()
                .collect::<Vec<_>>(),
            vec!["..", "bar", "baz"],
        );
        assert_eq!(
            "../foo/../bar//./baz"
                .normalized_components()
                .unwrap()
                .collect::<Vec<_>>(),
            vec!["..", "bar", "baz"],
        );
    }

    #[test]
    fn increasing_ancestors() {
        assert_eq!(
            "".increasing_ancestors().unwrap().collect::<Vec<_>>(),
            vec![""]
        );
        assert_eq!(
            "/".increasing_ancestors().unwrap().collect::<Vec<_>>(),
            vec!["/"]
        );
        assert_eq!(
            "//".increasing_ancestors().unwrap().collect::<Vec<_>>(),
            vec!["/", "//"]
        );
        assert_eq!(
            "a/../b".increasing_ancestors().unwrap().collect::<Vec<_>>(),
            vec!["", "a", "a/..", "a/../b"]
        );
        assert_eq!(
            "/a/../b"
                .increasing_ancestors()
                .unwrap()
                .collect::<Vec<_>>(),
            vec!["/", "/a", "/a/..", "/a/../b"]
        );
        assert_eq!(
            "/a/..//b"
                .increasing_ancestors()
                .unwrap()
                .collect::<Vec<_>>(),
            vec!["/", "/a", "/a/..", "/a/../", "/a/..//b"]
        );
        assert_eq!(
            "//a/..//b"
                .increasing_ancestors()
                .unwrap()
                .collect::<Vec<_>>(),
            vec!["/", "//a", "//a/..", "//a/../", "//a/..//b"]
        );
    }
}
