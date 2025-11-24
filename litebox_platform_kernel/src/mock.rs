pub type MockKernel = crate::LiteBoxKernel;

#[macro_export]
macro_rules! mock_log_println {
    ($($tt:tt)*) => {{
        use core::fmt::Write;
        let mut t: arrayvec::ArrayString<1024> = arrayvec::ArrayString::new();
        writeln!(t, $($tt)*).unwrap();
    }};
}
