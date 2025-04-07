use litebox_platform_multiplex::Platform;

pub(crate) enum Pipe {
    Reader(alloc::sync::Arc<crate::channel::Consumer<u8>>),
    Writer(alloc::sync::Arc<crate::channel::Producer<u8>>),
}

const PIPE_BUF_SIZE: usize = 1024 * 1024;

pub(crate) fn pipe(status_flags: litebox::fs::OFlags, platform: &'static Platform) -> (Pipe, Pipe) {
    if status_flags.contains(litebox::fs::OFlags::DIRECT) {
        todo!("O_DIRECT not supported");
    }

    let (producer, consumer) = crate::channel::Channel::new(PIPE_BUF_SIZE, platform).split();

    (Pipe::Reader(consumer), Pipe::Writer(producer))
}
