#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FillDrainOutcome {
    Done,
    Drained,
}

pub fn run_until_done_or_drained<T, S, R, D>(
    mut select_next: S,
    mut run_batch: R,
    drain_requested: D,
) -> FillDrainOutcome
where
    S: FnMut() -> Vec<T>,
    R: FnMut(Vec<T>),
    D: Fn() -> bool,
{
    loop {
        if drain_requested() {
            return FillDrainOutcome::Drained;
        }

        let batch = select_next();
        if batch.is_empty() {
            return FillDrainOutcome::Done;
        }

        run_batch(batch);
    }
}
