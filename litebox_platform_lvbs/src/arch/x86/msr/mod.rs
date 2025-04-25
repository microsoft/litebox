pub(crate) mod msr_instr;

#[expect(dead_code)]
#[expect(non_upper_case_globals)]
pub(crate) mod msr_index {
    include!(concat!(env!("OUT_DIR"), "/msr_index_bindings.rs"));
}
