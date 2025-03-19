mod systrap;

#[cfg(not(test))]
pub(crate) use systrap::init_sys_intercept;

#[cfg(test)]
pub fn init_sys_intercept() {
    // This is a no-op in test mode
}