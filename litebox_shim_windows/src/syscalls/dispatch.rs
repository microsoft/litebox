// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Decoding and dispatch of NT syscalls.
//!
//! Every supported NT syscall is listed once in the table inside [`Task::dispatch_nt_syscall`],
//! together with its arguments (in register and stack order) and its handler.

use litebox_common_linux::PtRegs;
use litebox_common_windows::NtSysno;
use litebox_common_windows::nt_status::NtStatus;

use super::{
    Handle, ProcessHandle, ThreadHandle, event, file, iocp, lpc, mm, sysinfo, trace,
    win_sys_req_arg, win_sys_req_ptr,
};
use crate::syscalls::registry::NtNotifyChangeKeyRequest;
use crate::syscalls::section::MapViewOfSectionParameters;
use crate::syscalls::timer::TimerCreateParameters;
use crate::syscalls::wait_completion_packet::WaitCompletionPacketAssociateParameters;
use crate::syscalls::worker_factory::WorkerFactoryCreateParameters;
use crate::{ShimPlatform, Task, nt_types, syscalls};

/// Expands the NT syscall table into a `match` on the syscall number.
///
/// Each entry is `Name(arg: Type [= decode], ...) => handler;`, where the arguments are listed in
/// register and stack order. An argument without `= decode` is converted from its raw value with
/// `ReinterpretTruncatedFromUsize`, `= *` decodes a guest pointer, and `= { convert }` truncates
/// the raw value to `convert`'s input type and maps it through `convert`. The handler is one of:
///
/// - `method`: a `Task` method called with the decoded arguments in table order;
/// - `method(Parameters)`: a `Task` method called with a `Parameters` struct whose fields are the
///   decoded arguments;
/// - a block that evaluates to the syscall's `NtStatus`.
macro_rules! nt_syscalls {
    (
        $task:ident, $ctx:ident;
        $(
            $name:ident($($arg:ident: $ty:ty $(= $decode:tt)?),* $(,)?)
                => $handler:tt $(($($parameters:tt)+))?;
        )*
    ) => {
        match NtSysno::from_raw($ctx.orig_rax) {
            $(
                Some(NtSysno::$name) => {
                    // Entries without arguments never advance the index iterator.
                    #[allow(unused_mut, unused_variables)]
                    let mut arg_indices = 0usize..;
                    $(
                        let Some($arg): Option<$ty> =
                            nt_syscalls!(@decode $ctx, arg_indices.next().unwrap() $(, $decode)?)
                        else {
                            litebox_util_log::error!(
                                syscall:? = NtSysno::$name,
                                argument = stringify!($arg);
                                "Failed to read Windows syscall argument"
                            );
                            return false;
                        };
                    )*
                    litebox_util_log::debug!(
                        syscall:? = NtSysno::$name;
                        "Handling Windows syscall"
                    );
                    let status: NtStatus =
                        nt_syscalls!(@handle $task [$($arg),*] $handler $(($($parameters)+))?);
                    $ctx.rax = status.as_raw().cast_unsigned() as usize;
                    true
                }
            )*
            _ => false,
        }
    };
    (@decode $ctx:ident, $index:expr) => {
        win_sys_req_arg::<Platform, _>($ctx, $index)
    };
    (@decode $ctx:ident, $index:expr, *) => {
        win_sys_req_ptr::<Platform, _, _>($ctx, $index)
    };
    (@decode $ctx:ident, $index:expr, { $convert:expr }) => {
        win_sys_req_arg::<Platform, _>($ctx, $index).map($convert)
    };
    (@handle $task:ident [$($arg:ident),*] $method:ident) => {
        $task.$method($($arg),*)
    };
    (@handle $task:ident [$($arg:ident),*] $method:ident ($($parameters:tt)+)) => {
        $task.$method($($parameters)+ { $($arg),* })
    };
    (@handle $task:ident [$($arg:ident),*] { $($body:tt)* }) => {{
        $($body)*
    }};
}

impl<Platform: ShimPlatform> Task<Platform> {
    /// Decodes the NT syscall in `ctx`, runs its handler, and stores the resulting status in
    /// `rax`.
    ///
    /// Returns `false` without running a handler if the syscall is not in the table or one of its
    /// arguments cannot be read. A successful `NtContinue` returns `true` without storing a
    /// status, leaving `rax` as restored from the new thread context.
    pub(crate) fn dispatch_nt_syscall(&self, ctx: &mut PtRegs) -> bool {
        nt_syscalls! {
            self, ctx;
            NtAccessCheck(
                security_descriptor: Platform::RawConstPointer<u8> = *,
                client_token: Handle,
                desired_access: u32,
                generic_mapping: Platform::RawConstPointer<[u32; 4]> = *,
                privilege_set: Platform::RawMutPointer<u8> = *,
                privilege_set_length: Platform::RawMutPointer<u32> = *,
                granted_access: Platform::RawMutPointer<u32> = *,
                access_status: Platform::RawMutPointer<u32> = *,
            ) => sys_nt_access_check(syscalls::token::AccessCheckParameters);
            NtClose(handle: Handle) => sys_nt_close;
            NtDuplicateObject(
                source_process_handle: ProcessHandle,
                source_handle: Handle,
                target_process_handle: ProcessHandle,
                target_handle: Option<Platform::RawMutPointer<Handle>> = *,
                desired_access: u32,
                handle_attributes: u32,
                options: u32,
            ) => sys_nt_duplicate_object;
            NtCreateEvent(
                event_handle: Platform::RawMutPointer<Handle> = *,
                desired_access: u32,
                object_attributes: Option<Platform::RawConstPointer<nt_types::ObjectAttributes>> = *,
                event_type: u32,
                initial_state: bool,
            ) => sys_nt_create_event;
            NtCreateMutant(
                mutant_handle: Platform::RawMutPointer<Handle> = *,
                desired_access: u32,
                object_attributes: Option<Platform::RawConstPointer<nt_types::ObjectAttributes>> = *,
                initial_owner: bool,
            ) => sys_nt_create_mutant;
            NtCreateSemaphore(
                semaphore_handle: Platform::RawMutPointer<Handle> = *,
                desired_access: u32,
                object_attributes: Option<Platform::RawConstPointer<nt_types::ObjectAttributes>> = *,
                initial_count: i32,
                maximum_count: i32,
            ) => sys_nt_create_semaphore;
            NtCreateDirectoryObject(
                directory_handle: Platform::RawMutPointer<Handle> = *,
                desired_access: u32,
                object_attributes: Option<Platform::RawConstPointer<nt_types::ObjectAttributes>> = *,
            ) => {
                self.sys_nt_create_directory_object(
                    directory_handle,
                    desired_access,
                    object_attributes,
                    syscalls::Handle::default(),
                    0,
                )
            };
            NtCreateDirectoryObjectEx(
                directory_handle: Platform::RawMutPointer<Handle> = *,
                desired_access: u32,
                object_attributes: Option<Platform::RawConstPointer<nt_types::ObjectAttributes>> = *,
                shadow_directory_handle: Handle,
                flags: u32,
            ) => sys_nt_create_directory_object;
            NtOpenDirectoryObject(
                directory_handle: Platform::RawMutPointer<Handle> = *,
                desired_access: u32,
                object_attributes: Option<Platform::RawConstPointer<nt_types::ObjectAttributes>> = *,
            ) => sys_nt_open_directory_object;
            NtOpenSection(
                section_handle: Platform::RawMutPointer<Handle> = *,
                desired_access: u32,
                object_attributes: Option<Platform::RawConstPointer<nt_types::ObjectAttributes>> = *,
            ) => sys_nt_open_section;
            NtQueryDirectoryObject(
                directory_handle: Handle,
                buffer: Platform::RawMutPointer<u8> = *,
                buffer_length: u32,
                return_single_entry: bool,
                restart_scan: bool,
                context: Platform::RawMutPointer<u32> = *,
                return_length: Option<Platform::RawMutPointer<u32>> = *,
            ) => sys_nt_query_directory_object(syscalls::object_manager::DirectoryQueryParameters);
            NtCreateSymbolicLinkObject(
                link_handle: Platform::RawMutPointer<Handle> = *,
                desired_access: u32,
                object_attributes: Option<Platform::RawConstPointer<nt_types::ObjectAttributes>> = *,
                link_target: Platform::RawConstPointer<nt_types::UnicodeString> = *,
            ) => sys_nt_create_symbolic_link_object;
            NtOpenSymbolicLinkObject(
                link_handle: Platform::RawMutPointer<Handle> = *,
                desired_access: u32,
                object_attributes: Option<Platform::RawConstPointer<nt_types::ObjectAttributes>> = *,
            ) => sys_nt_open_symbolic_link_object;
            NtQuerySymbolicLinkObject(
                link_handle: Handle,
                link_target: Platform::RawMutPointer<nt_types::UnicodeString> = *,
                returned_length: Option<Platform::RawMutPointer<u32>> = *,
            ) => sys_nt_query_symbolic_link_object;
            NtCreateIoCompletion(
                io_completion_handle: Platform::RawMutPointer<Handle> = *,
                desired_access: u32,
                object_attributes: Option<Platform::RawConstPointer<nt_types::ObjectAttributes>> = *,
                number_of_concurrent_threads: u32,
            ) => sys_nt_create_io_completion;
            NtOpenIoCompletion(
                io_completion_handle: Platform::RawMutPointer<Handle> = *,
                desired_access: u32,
                object_attributes: Option<Platform::RawConstPointer<nt_types::ObjectAttributes>> = *,
            ) => sys_nt_open_io_completion;
            NtSetIoCompletion(
                io_completion_handle: Handle,
                completion_key: usize,
                completion_value: usize,
                status: i32,
                information: usize,
            ) => sys_nt_set_io_completion;
            NtRemoveIoCompletionEx(
                io_completion_handle: Handle,
                io_completion_information: Platform::RawMutPointer<iocp::IoCompletionPacket> = *,
                count: u32,
                num_entries_removed: Platform::RawMutPointer<u32> = *,
                timeout: Option<Platform::RawConstPointer<i64>> = *,
                alertable: bool,
            ) => sys_nt_remove_io_completion_ex;
            NtAlpcConnectPort(
                port_handle: Platform::RawMutPointer<Handle> = *,
                port_name: Platform::RawConstPointer<nt_types::UnicodeString> = *,
            ) => {
                Self::sys_nt_alpc_connect_port(port_handle, port_name)
            };
            NtConnectPort(
                port_handle: Platform::RawMutPointer<Handle> = *,
                port_name: Platform::RawConstPointer<nt_types::UnicodeString> = *,
                security_qos: Platform::RawConstPointer<lpc::SecurityQualityOfService> = *,
                client_view: Option<Platform::RawMutPointer<lpc::PortView>> = *,
                server_view: Option<Platform::RawMutPointer<lpc::RemotePortView>> = *,
                max_message_length: Option<Platform::RawMutPointer<u32>> = *,
                connection_information: Option<Platform::RawMutPointer<u8>> = *,
                connection_information_length: Option<Platform::RawMutPointer<u32>> = *,
            ) => sys_nt_connect_port(syscalls::lpc::ConnectPortParameters);
            NtAlpcSendWaitReceivePort(
                port_handle: Handle,
                flags: lpc::AlpcMessageFlags = { lpc::AlpcMessageFlags::from_bits_retain },
                send_message: Platform::RawMutPointer<u8> = *,
                send_message_attributes: Option<Platform::RawConstPointer<u8>> = *,
                receive_message: Platform::RawMutPointer<u8> = *,
                buffer_length: Platform::RawMutPointer<usize> = *,
                receive_message_attributes: Option<Platform::RawMutPointer<u8>> = *,
                timeout: Option<Platform::RawConstPointer<i64>> = *,
            ) => sys_nt_alpc_send_wait_receive_port;
            // `NtSecureConnectPort` carries SID and server-view semantics that are
            // deliberately outside the current CSR `NtConnectPort` subset.
            NtSecureConnectPort() => {
                litebox_util_log::debug!(
                    "Rejected NtSecureConnectPort; only the CSR NtConnectPort subset is modeled"
                );
                NtStatus::NOT_SUPPORTED
            };
            NtCreateSection(
                section_handle: Platform::RawMutPointer<Handle> = *,
                desired_access: u32,
                object_attributes: Option<Platform::RawConstPointer<nt_types::ObjectAttributes>> = *,
                maximum_size: Option<Platform::RawConstPointer<i64>> = *,
                section_page_protection: u32,
                allocation_attributes: u32,
                file_handle: Handle,
            ) => sys_nt_create_section;
            NtCreateSectionEx(
                section_handle: Platform::RawMutPointer<Handle> = *,
                desired_access: u32,
                object_attributes: Option<Platform::RawConstPointer<nt_types::ObjectAttributes>> = *,
                maximum_size: Option<Platform::RawConstPointer<i64>> = *,
                section_page_protection: u32,
                allocation_attributes: u32,
                file_handle: Handle,
                extended_parameters: Option<Platform::RawConstPointer<u8>> = *,
                extended_parameter_count: u32,
            ) => sys_nt_create_section_ex;
            NtCreateWaitCompletionPacket(
                wait_completion_packet_handle: Platform::RawMutPointer<Handle> = *,
                desired_access: u32,
                object_attributes: Option<Platform::RawConstPointer<nt_types::ObjectAttributes>> = *,
            ) => sys_nt_create_wait_completion_packet;
            NtAssociateWaitCompletionPacket(
                wait_completion_packet_handle: Handle,
                io_completion_handle: Handle,
                target_object_handle: Handle,
                key_context: usize,
                apc_context: usize,
                io_status: i32,
                io_status_information: usize,
                already_signaled: Option<Platform::RawMutPointer<u8>> = *,
            ) => sys_nt_associate_wait_completion_packet(WaitCompletionPacketAssociateParameters);
            NtCancelWaitCompletionPacket(
                wait_completion_packet_handle: Handle,
                remove_signaled_packet: bool,
            ) => sys_nt_cancel_wait_completion_packet;
            NtCreateWorkerFactory(
                worker_factory_handle: Platform::RawMutPointer<Handle> = *,
                desired_access: u32,
                object_attributes: Option<Platform::RawConstPointer<nt_types::ObjectAttributes>> = *,
                completion_port_handle: Handle,
                worker_process_handle: ProcessHandle,
                start_routine: usize,
                start_parameter: usize,
                max_thread_count: u32,
                stack_reserve: usize,
                stack_commit: usize,
            ) => sys_nt_create_worker_factory(WorkerFactoryCreateParameters);
            NtSetInformationWorkerFactory(
                worker_factory_handle: Handle,
                worker_factory_information_class: u32,
                worker_factory_information: Platform::RawConstPointer<u8> = *,
                worker_factory_information_length: u32,
            ) => sys_nt_set_information_worker_factory;
            NtShutdownWorkerFactory(
                worker_factory_handle: Handle,
                pending_worker_count: Platform::RawMutPointer<i32> = *,
            ) => sys_nt_shutdown_worker_factory;
            NtCreateTimer2(
                timer_handle: Platform::RawMutPointer<Handle> = *,
                timer_id: Option<Platform::RawConstPointer<u32>> = *,
                object_attributes: Option<Platform::RawConstPointer<nt_types::ObjectAttributes>> = *,
                attributes: u32,
                desired_access: u32,
            ) => sys_nt_create_timer2(TimerCreateParameters);
            NtSetTimer2(
                timer_handle: Handle,
                due_time: Option<Platform::RawConstPointer<i64>> = *,
                period: Option<Platform::RawConstPointer<i64>> = *,
                parameters: Option<Platform::RawConstPointer<u8>> = *,
            ) => sys_nt_set_timer2;
            NtOpenEvent(
                event_handle: Platform::RawMutPointer<Handle> = *,
                desired_access: u32,
                object_attributes: Option<Platform::RawConstPointer<nt_types::ObjectAttributes>> = *,
            ) => sys_nt_open_event;
            NtOpenMutant(
                mutant_handle: Platform::RawMutPointer<Handle> = *,
                desired_access: u32,
                object_attributes: Option<Platform::RawConstPointer<nt_types::ObjectAttributes>> = *,
            ) => sys_nt_open_mutant;
            NtOpenSemaphore(
                semaphore_handle: Platform::RawMutPointer<Handle> = *,
                desired_access: u32,
                object_attributes: Option<Platform::RawConstPointer<nt_types::ObjectAttributes>> = *,
            ) => sys_nt_open_semaphore;
            NtReleaseMutant(
                mutant_handle: Handle,
                previous_count: Option<Platform::RawMutPointer<i32>> = *,
            ) => sys_nt_release_mutant;
            NtReleaseSemaphore(
                semaphore_handle: Handle,
                release_count: i32,
                previous_count: Option<Platform::RawMutPointer<i32>> = *,
            ) => sys_nt_release_semaphore;
            NtSetEvent(
                event_handle: Handle,
                previous_state: Option<Platform::RawMutPointer<i32>> = *,
            ) => sys_nt_set_event;
            NtResetEvent(
                event_handle: Handle,
                previous_state: Option<Platform::RawMutPointer<i32>> = *,
            ) => sys_nt_reset_event;
            NtClearEvent(event_handle: Handle) => sys_nt_clear_event;
            NtPulseEvent(
                event_handle: Handle,
                previous_state: Option<Platform::RawMutPointer<i32>> = *,
            ) => sys_nt_pulse_event;
            NtQueryEvent(
                event_handle: Handle,
                event_information_class: u32,
                event_information: Platform::RawMutPointer<event::EventBasicInformation> = *,
                event_information_length: u32,
                return_length: Option<Platform::RawMutPointer<u32>> = *,
            ) => sys_nt_query_event;
            NtQueryMutant(
                mutant_handle: Handle,
                mutant_information_class: u32,
                mutant_information: Platform::RawMutPointer<u8> = *,
                mutant_information_length: u32,
                return_length: Option<Platform::RawMutPointer<u32>> = *,
            ) => sys_nt_query_mutant;
            NtSetEventBoostPriority(event_handle: Handle) => {
                self.sys_nt_set_event_boost_priority(event_handle)
            };
            NtOpenFile(
                file_handle: Platform::RawMutPointer<Handle> = *,
                desired_access: u32,
                object_attributes: Option<Platform::RawConstPointer<nt_types::ObjectAttributes>> = *,
                io_status_block: Platform::RawMutPointer<nt_types::IoStatusBlock> = *,
                share_access: u32,
                open_options: u32,
            ) => sys_nt_open_file;
            NtQueryAttributesFile(
                object_attributes: Option<Platform::RawConstPointer<nt_types::ObjectAttributes>> = *,
                file_information: Platform::RawMutPointer<file::FileBasicInformation> = *,
            ) => sys_nt_query_attributes_file;
            NtQueryFullAttributesFile(
                object_attributes: Option<Platform::RawConstPointer<nt_types::ObjectAttributes>> = *,
                file_information: Platform::RawMutPointer<file::FileNetworkOpenInformation> = *,
            ) => sys_nt_query_full_attributes_file;
            NtQueryInformationByName(
                object_attributes: Option<Platform::RawConstPointer<nt_types::ObjectAttributes>> = *,
                io_status_block: Platform::RawMutPointer<nt_types::IoStatusBlock> = *,
                file_information: Platform::RawMutPointer<u8> = *,
                length: u32,
                file_information_class: u32,
            ) => sys_nt_query_information_by_name;
            NtQueryInformationFile(
                file_handle: Handle,
                io_status_block: Platform::RawMutPointer<nt_types::IoStatusBlock> = *,
                file_information: Platform::RawMutPointer<u8> = *,
                length: u32,
                file_information_class: u32,
            ) => sys_nt_query_information_file;
            NtSetInformationFile(
                file_handle: Handle,
                io_status_block: Platform::RawMutPointer<nt_types::IoStatusBlock> = *,
                file_information: Platform::RawConstPointer<u8> = *,
                length: u32,
                file_information_class: u32,
            ) => sys_nt_set_information_file;
            NtCreateFile(
                file_handle: Platform::RawMutPointer<Handle> = *,
                desired_access: u32,
                object_attributes: Option<Platform::RawConstPointer<nt_types::ObjectAttributes>> = *,
                io_status_block: Platform::RawMutPointer<nt_types::IoStatusBlock> = *,
                allocation_size: Option<Platform::RawConstPointer<i64>> = *,
                file_attributes: u32,
                share_access: u32,
                create_disposition: u32,
                create_options: u32,
                ea_buffer: Option<Platform::RawConstPointer<u8>> = *,
                ea_length: u32,
            ) => sys_nt_create_file;
            NtWriteFile(
                file_handle: Handle,
                event: Handle,
                apc_routine: Option<Platform::RawConstPointer<u8>> = *,
                apc_context: Option<Platform::RawConstPointer<u8>> = *,
                io_status_block: Platform::RawMutPointer<nt_types::IoStatusBlock> = *,
                buffer: Platform::RawConstPointer<u8> = *,
                length: u32,
                byte_offset: Option<Platform::RawConstPointer<i64>> = *,
                key: Option<Platform::RawConstPointer<u32>> = *,
            ) => sys_nt_write_file;
            NtReadFile(
                file_handle: Handle,
                event: Handle,
                apc_routine: Option<Platform::RawConstPointer<u8>> = *,
                apc_context: Option<Platform::RawConstPointer<u8>> = *,
                io_status_block: Platform::RawMutPointer<nt_types::IoStatusBlock> = *,
                buffer: Platform::RawMutPointer<u8> = *,
                length: u32,
                byte_offset: Option<Platform::RawConstPointer<i64>> = *,
                key: Option<Platform::RawConstPointer<u32>> = *,
            ) => sys_nt_read_file;
            NtGetCurrentProcessorNumberEx(
                processor_number: Platform::RawMutPointer<sysinfo::ProcessorNumber> = *,
            ) => {
                self.sys_nt_get_current_processor_number_ex(processor_number)
            };
            NtQueryDebugFilterState(component_id: u32, level: u32) => {
                litebox_util_log::debug!(
                    component_id,
                    level;
                    "NtQueryDebugFilterState reports no attached debugger"
                );
                NtStatus::DEBUGGER_INACTIVE
            };
            NtQueryDirectoryFileEx(
                file_handle: Handle,
                event: Handle,
                apc_routine: Option<Platform::RawConstPointer<u8>> = *,
                apc_context: Option<Platform::RawConstPointer<u8>> = *,
                io_status_block: Platform::RawMutPointer<nt_types::IoStatusBlock> = *,
                file_information: Platform::RawMutPointer<u8> = *,
                length: u32,
                file_information_class: u32,
                query_flags: u32,
                file_name: Option<Platform::RawConstPointer<nt_types::UnicodeString>> = *,
            ) => sys_nt_query_directory_file_ex;
            NtQueryVolumeInformationFile(
                file_handle: Handle,
                io_status_block: Platform::RawMutPointer<nt_types::IoStatusBlock> = *,
                fs_information: Platform::RawMutPointer<u8> = *,
                length: u32,
                fs_information_class: u32,
            ) => sys_nt_query_volume_information_file;
            NtDeviceIoControlFile(
                file_handle: Handle,
                event: Handle,
                apc_routine: Option<Platform::RawConstPointer<u8>> = *,
                apc_context: Option<Platform::RawConstPointer<u8>> = *,
                io_status_block: Platform::RawMutPointer<nt_types::IoStatusBlock> = *,
                io_control_code: u32,
                input_buffer: Option<Platform::RawConstPointer<u8>> = *,
                input_buffer_length: u32,
                output_buffer: Option<Platform::RawMutPointer<u8>> = *,
                output_buffer_length: u32,
            ) => sys_nt_device_io_control_file;
            NtApphelpCacheControl(
                service_class: u32,
                service_data: Option<Platform::RawMutPointer<nt_types::AhcServiceData>> = *,
            ) => {
                syscalls::apphelp::sys_nt_apphelp_cache_control::<Platform>(
                    service_class,
                    service_data,
                )
            };
            NtCreateKey(
                key_handle: Platform::RawMutPointer<Handle> = *,
                desired_access: u32,
                object_attributes: Option<Platform::RawConstPointer<nt_types::ObjectAttributes>> = *,
                title_index: u32,
                class: Option<Platform::RawConstPointer<nt_types::UnicodeString>> = *,
                create_options: u32,
                disposition: Option<Platform::RawMutPointer<u32>> = *,
            ) => sys_nt_create_key;
            NtOpenKey(
                key_handle: Platform::RawMutPointer<Handle> = *,
                desired_access: u32,
                object_attributes: Option<Platform::RawConstPointer<nt_types::ObjectAttributes>> = *,
            ) => sys_nt_open_key;
            NtOpenKeyEx(
                key_handle: Platform::RawMutPointer<Handle> = *,
                desired_access: u32,
                object_attributes: Option<Platform::RawConstPointer<nt_types::ObjectAttributes>> = *,
                open_options: u32,
            ) => {
                self.sys_nt_open_key_ex(key_handle, desired_access, object_attributes, open_options)
            };
            NtQueryKey(
                key_handle: Handle,
                key_information_class: u32,
                key_information: Platform::RawMutPointer<u8> = *,
                length: u32,
                result_length: Platform::RawMutPointer<u32> = *,
            ) => sys_nt_query_key;
            NtSetInformationKey(
                key_handle: Handle,
                key_set_information_class: u32,
                key_set_information: Platform::RawConstPointer<u8> = *,
                key_set_information_length: u32,
            ) => sys_nt_set_information_key;
            NtEnumerateKey(
                key_handle: Handle,
                index: u32,
                key_information_class: u32,
                key_information: Platform::RawMutPointer<u8> = *,
                length: u32,
                result_length: Platform::RawMutPointer<u32> = *,
            ) => sys_nt_enumerate_key;
            NtQueryValueKey(
                key_handle: Handle,
                value_name: Platform::RawConstPointer<nt_types::UnicodeString> = *,
                key_value_information_class: u32,
                key_value_information: Platform::RawMutPointer<u8> = *,
                length: u32,
                result_length: Platform::RawMutPointer<u32> = *,
            ) => sys_nt_query_value_key;
            NtEnumerateValueKey(
                key_handle: Handle,
                index: u32,
                key_value_information_class: u32,
                key_value_information: Platform::RawMutPointer<u8> = *,
                length: u32,
                result_length: Platform::RawMutPointer<u32> = *,
            ) => sys_nt_enumerate_value_key;
            NtSetValueKey(
                key_handle: Handle,
                value_name: Platform::RawConstPointer<nt_types::UnicodeString> = *,
                title_index: u32,
                value_type: u32,
                data: Option<Platform::RawConstPointer<u8>> = *,
                data_size: u32,
            ) => sys_nt_set_value_key;
            NtNotifyChangeKey(
                key_handle: Handle,
                event: Handle,
                apc_routine: Option<Platform::RawConstPointer<u8>> = *,
                apc_context: Option<Platform::RawConstPointer<u8>> = *,
                io_status_block: Platform::RawMutPointer<nt_types::IoStatusBlock> = *,
                completion_filter: u32,
                watch_tree: bool,
                buffer: Option<Platform::RawMutPointer<u8>> = *,
                buffer_size: u32,
                asynchronous: bool,
            ) => sys_nt_notify_change_key(NtNotifyChangeKeyRequest);
            NtGetMUIRegistryInfo(
                flags: u32,
                data_size: Option<Platform::RawMutPointer<u32>> = *,
                data: Option<Platform::RawMutPointer<u8>> = *,
            ) => sys_nt_get_mui_registry_info;
            NtGetNlsSectionPtr(
                section_type: u32,
                section_data: u32,
                context_data: usize,
                section_pointer: Platform::RawMutPointer<usize> = *,
                section_size: Option<Platform::RawMutPointer<u32>> = *,
            ) => sys_nt_get_nls_section_ptr;
            NtInitializeNlsFiles(
                base_address: Platform::RawMutPointer<usize> = *,
                default_locale_id: Platform::RawMutPointer<u32> = *,
                default_casing_table_size: Platform::RawMutPointer<i64> = *,
            ) => sys_nt_initialize_nls_files;
            NtQueryDefaultLocale(
                user_profile: bool,
                default_locale_id: Platform::RawMutPointer<u32> = *,
            ) => sys_nt_query_default_locale;
            NtSetDefaultLocale(
                user_profile: bool,
                default_locale_id: u32,
            ) => sys_nt_set_default_locale;
            NtQueryDefaultUILanguage(
                default_ui_language: Platform::RawMutPointer<u16> = *,
            ) => sys_nt_query_default_ui_language;
            NtSetDefaultUILanguage(default_ui_language: u16) => sys_nt_set_default_ui_language;
            NtQueryInstallUILanguage(
                install_ui_language: Platform::RawMutPointer<u16> = *,
            ) => sys_nt_query_install_ui_language;
            NtQueryPerformanceCounter(
                performance_counter: Platform::RawMutPointer<i64> = *,
                performance_frequency: Option<Platform::RawMutPointer<i64>> = *,
            ) => sys_nt_query_performance_counter;
            NtQueryTimerResolution(
                minimum_resolution: Platform::RawMutPointer<u32> = *,
                maximum_resolution: Platform::RawMutPointer<u32> = *,
                current_resolution: Platform::RawMutPointer<u32> = *,
            ) => {
                Self::sys_nt_query_timer_resolution(
                    minimum_resolution,
                    maximum_resolution,
                    current_resolution,
                )
            };
            NtQueryLicenseValue(
                value_name: Platform::RawConstPointer<nt_types::UnicodeString> = *,
                value_type: Platform::RawMutPointer<u32> = *,
                data: Platform::RawMutPointer<u8> = *,
                data_size: u32,
                result_data_size: Platform::RawMutPointer<u32> = *,
            ) => {
                Self::sys_nt_query_license_value(
                    value_name,
                    value_type,
                    data,
                    data_size,
                    result_data_size,
                )
            };
            NtQuerySystemInformation(
                system_information_class: u32,
                system_information: Platform::RawMutPointer<u8> = *,
                system_information_length: u32,
                return_length: Option<Platform::RawMutPointer<u32>> = *,
            ) => {
                Self::sys_nt_query_system_information(
                    system_information_class,
                    system_information,
                    system_information_length,
                    return_length,
                )
            };
            NtQuerySystemInformationEx(
                system_information_class: u32,
                input_buffer: Option<Platform::RawConstPointer<u8>> = *,
                input_buffer_length: u32,
                system_information: Platform::RawMutPointer<u8> = *,
                system_information_length: u32,
                return_length: Option<Platform::RawMutPointer<u32>> = *,
            ) => {
                Self::sys_nt_query_system_information_ex(
                    system_information_class,
                    input_buffer,
                    input_buffer_length,
                    system_information,
                    system_information_length,
                    return_length,
                )
            };
            NtQueryWnfStateData(
                state_name: Platform::RawConstPointer<u64> = *,
                type_id: Option<Platform::RawConstPointer<nt_types::Guid>> = *,
                explicit_scope: Option<Platform::RawConstPointer<u8>> = *,
                change_stamp: Platform::RawMutPointer<u32> = *,
                buffer: Platform::RawMutPointer<u8> = *,
                buffer_size: Platform::RawMutPointer<u32> = *,
            ) => sys_nt_query_wnf_state_data;
            NtCreateWnfStateName(
                state_name: Platform::RawMutPointer<u64> = *,
                name_lifetime: u32,
                data_scope: u32,
                persist_data: bool,
                type_id: Option<Platform::RawConstPointer<nt_types::Guid>> = *,
                maximum_state_size: u32,
                security_descriptor: Platform::RawConstPointer<u8> = *,
            ) => sys_nt_create_wnf_state_name(syscalls::wnf::WnfCreateStateNameParameters);
            NtUpdateWnfStateData(
                state_name: Platform::RawConstPointer<u64> = *,
                buffer: Option<Platform::RawConstPointer<u8>> = *,
                buffer_size: u32,
                type_id: Option<Platform::RawConstPointer<nt_types::Guid>> = *,
                explicit_scope: Option<Platform::RawConstPointer<u8>> = *,
                matching_change_stamp: u32,
                check_stamp: i32,
            ) => sys_nt_update_wnf_state_data(syscalls::wnf::WnfUpdateStateDataParameters);
            NtDeleteWnfStateData(
                state_name: Platform::RawConstPointer<u64> = *,
                explicit_scope: Option<Platform::RawConstPointer<u8>> = *,
            ) => sys_nt_delete_wnf_state_data;
            NtDeleteWnfStateName(state_name: Platform::RawConstPointer<u64> = *) => {
                self.sys_nt_delete_wnf_state_name(state_name)
            };
            NtQueryWnfStateNameInformation(
                state_name: Platform::RawConstPointer<u64> = *,
                name_information_class: u32,
                explicit_scope: Option<Platform::RawConstPointer<u8>> = *,
                buffer: Platform::RawMutPointer<u32> = *,
                buffer_size: u32,
            ) => sys_nt_query_wnf_state_name_information;
            NtSetWnfProcessNotificationEvent(notification_event: Handle) => {
                self.sys_nt_set_wnf_process_notification_event(notification_event)
            };
            NtGetCompleteWnfStateSubscription(
                old_state_name: Option<Platform::RawConstPointer<u64>> = *,
                old_subscription_id: Option<Platform::RawConstPointer<u64>> = *,
                old_event_mask: u32,
                old_status: i32,
                delivery_descriptor: Platform::RawMutPointer<u8> = *,
                descriptor_size: u32,
            ) => sys_nt_get_complete_wnf_state_subscription;
            NtSubscribeWnfStateChange(
                state_name: Platform::RawConstPointer<u64> = *,
                change_stamp: u32,
                event_mask: u32,
                subscription_id: Option<Platform::RawMutPointer<u64>> = *,
            ) => sys_nt_subscribe_wnf_state_change;
            NtUnsubscribeWnfStateChange(state_name: Platform::RawConstPointer<u64> = *) => {
                self.sys_nt_unsubscribe_wnf_state_change(state_name)
            };
            NtQuerySection(
                section_handle: Handle,
                section_information_class: u32,
                section_information: Platform::RawMutPointer<u8> = *,
                section_information_length: usize,
                return_length: Option<Platform::RawMutPointer<usize>> = *,
            ) => sys_nt_query_section;
            NtQueryObject(
                handle: Handle,
                object_information_class: u32,
                object_information: Platform::RawMutPointer<u8> = *,
                object_information_length: u32,
                return_length: Option<Platform::RawMutPointer<u32>> = *,
            ) => sys_nt_query_object;
            NtSetInformationObject(
                handle: Handle,
                object_information_class: u32,
                object_information: Platform::RawConstPointer<u8> = *,
                object_information_length: u32,
            ) => sys_nt_set_information_object;
            NtQueryInformationProcess(
                process_handle: ProcessHandle,
                process_information_class: u32,
                process_information: Platform::RawMutPointer<u8> = *,
                process_information_length: u32,
                return_length: Option<Platform::RawMutPointer<u32>> = *,
            ) => sys_nt_query_information_process;
            NtSetInformationProcess(
                process_handle: ProcessHandle,
                process_information_class: u32,
                process_information: Platform::RawMutPointer<u8> = *,
                process_information_length: u32,
            ) => sys_nt_set_information_process;
            NtSetInformationThread(
                thread_handle: ThreadHandle,
                thread_information_class: u32,
                thread_information: Platform::RawConstPointer<u8> = *,
                thread_information_length: u32,
            ) => {
                Self::sys_nt_set_information_thread(
                    thread_handle,
                    thread_information_class,
                    thread_information,
                    thread_information_length,
                )
            };
            NtQueryInformationThread(
                thread_handle: ThreadHandle,
                thread_information_class: u32,
                thread_information: Platform::RawMutPointer<u8> = *,
                thread_information_length: u32,
                return_length: Option<Platform::RawMutPointer<u32>> = *,
            ) => sys_nt_query_information_thread;
            NtCreateThreadEx(
                thread_handle: Platform::RawMutPointer<Handle> = *,
                desired_access: u32,
                object_attributes: Option<Platform::RawConstPointer<nt_types::ObjectAttributes>> = *,
                process_handle: ProcessHandle,
                start_routine: usize,
                argument: usize,
                create_flags: u32,
                zero_bits: usize,
                stack_size: usize,
                maximum_stack_size: usize,
                attribute_list: Option<Platform::RawConstPointer<u8>> = *,
            ) => {
                self.sys_nt_create_thread_ex(
                    ctx,
                    thread_handle,
                    desired_access,
                    object_attributes,
                    process_handle,
                    start_routine,
                    argument,
                    create_flags,
                    zero_bits,
                    stack_size,
                    maximum_stack_size,
                    attribute_list,
                )
            };
            NtResumeThread(
                thread_handle: ThreadHandle,
                previous_suspend_count: Option<Platform::RawMutPointer<u32>> = *,
            ) => sys_nt_resume_thread;
            NtAlertThread(thread_handle: ThreadHandle) => {
                self.sys_nt_alert_thread(thread_handle)
            };
            NtWaitForAlertByThreadId(
                address: usize,
                timeout: Option<Platform::RawConstPointer<i64>> = *,
            ) => {
                self.sys_nt_wait_for_alert_by_thread_id(address, timeout)
            };
            NtAlertThreadByThreadIdEx(thread_id: usize, lock: usize) => {
                self.sys_nt_alert_thread_by_thread_id_ex(thread_id, lock)
            };
            NtAlertThreadByThreadId(thread_id: usize) => {
                self.sys_nt_alert_thread_by_thread_id(thread_id)
            };
            NtWaitForSingleObject(
                handle: Handle,
                alertable: bool,
                timeout: Option<Platform::RawConstPointer<i64>> = *,
            ) => sys_nt_wait_for_single_object;
            NtDelayExecution(
                alertable: bool,
                delay_interval: Platform::RawConstPointer<i64> = *,
            ) => sys_nt_delay_execution;
            NtOpenThreadToken(
                thread_handle: ThreadHandle,
                desired_access: u32,
                open_as_self: u32,
                token_handle: Platform::RawMutPointer<Handle> = *,
            ) => {
                Self::sys_nt_open_thread_token(
                    thread_handle,
                    desired_access,
                    open_as_self,
                    token_handle,
                )
            };
            NtOpenThreadTokenEx(
                thread_handle: ThreadHandle,
                desired_access: u32,
                open_as_self: u32,
                handle_attributes: u32,
                token_handle: Platform::RawMutPointer<Handle> = *,
            ) => {
                Self::sys_nt_open_thread_token_ex(
                    thread_handle,
                    desired_access,
                    open_as_self,
                    handle_attributes,
                    token_handle,
                )
            };
            NtOpenProcessToken(
                process_handle: ProcessHandle,
                desired_access: u32,
                token_handle: Platform::RawMutPointer<Handle> = *,
            ) => sys_nt_open_process_token;
            NtOpenProcessTokenEx(
                process_handle: ProcessHandle,
                desired_access: u32,
                handle_attributes: u32,
                token_handle: Platform::RawMutPointer<Handle> = *,
            ) => sys_nt_open_process_token_ex;
            NtQueryInformationToken(
                token_handle: Handle,
                token_information_class: u32,
                token_information: Platform::RawMutPointer<u8> = *,
                token_information_length: u32,
                return_length: Platform::RawMutPointer<u32> = *,
            ) => sys_nt_query_information_token;
            NtQuerySecurityAttributesToken(
                token_handle: Handle,
                attributes: Platform::RawConstPointer<nt_types::UnicodeString> = *,
                number_of_attributes: u32,
                buffer: Platform::RawMutPointer<u8> = *,
                length: u32,
                return_length: Platform::RawMutPointer<u32> = *,
            ) => sys_nt_query_security_attributes_token;
            NtConvertBetweenAuxiliaryCounterAndPerformanceCounter(
                flag: u32,
                source: Platform::RawConstPointer<u64> = *,
                destination: Platform::RawMutPointer<u64> = *,
                conversion_error: Option<Platform::RawMutPointer<u64>> = *,
            ) => {
                Self::sys_nt_convert_between_auxiliary_counter_and_performance_counter(
                    flag,
                    source,
                    destination,
                    conversion_error,
                )
            };
            NtTraceEvent(
                trace_handle: Handle,
                flags: u32,
                field_size: u32,
                fields: Platform::RawConstPointer<trace::EventHeader> = *,
            ) => sys_nt_trace_event;
            NtTraceControl(
                function_code: u32,
                input_buffer: Platform::RawConstPointer<u32> = *,
                input_buffer_length: u32,
                output_buffer: Option<Platform::RawMutPointer<u8>> = *,
                output_buffer_length: u32,
                return_length: Platform::RawMutPointer<u32> = *,
            ) => sys_nt_trace_control;
            NtAllocateVirtualMemory(
                process_handle: ProcessHandle,
                base_address: Platform::RawMutPointer<usize> = *,
                zero_bits: usize,
                region_size: Platform::RawMutPointer<usize> = *,
                allocation_type: u32,
                protect: u32,
            ) => sys_nt_allocate_virtual_memory;
            NtAllocateVirtualMemoryEx(
                process_handle: ProcessHandle,
                base_address: Platform::RawMutPointer<usize> = *,
                region_size: Platform::RawMutPointer<usize> = *,
                allocation_type: u32,
                protect: u32,
                extended_parameters: Option<Platform::RawConstPointer<mm::MemoryExtendedParameter>> = *,
                extended_parameter_count: u32,
            ) => {
                self.sys_nt_allocate_virtual_memory_ex(
                    process_handle,
                    base_address,
                    region_size,
                    allocation_type,
                    protect,
                    mm::MemoryExtendedParameters {
                        parameters: extended_parameters,
                        count: extended_parameter_count,
                    },
                )
            };
            NtFreeVirtualMemory(
                process_handle: ProcessHandle,
                base_address: Platform::RawMutPointer<usize> = *,
                region_size: Platform::RawMutPointer<usize> = *,
                free_type: u32,
            ) => sys_nt_free_virtual_memory;
            NtProtectVirtualMemory(
                process_handle: ProcessHandle,
                base_address: Platform::RawMutPointer<usize> = *,
                region_size: Platform::RawMutPointer<usize> = *,
                new_protect: u32,
                old_protect: Platform::RawMutPointer<u32> = *,
            ) => sys_nt_protect_virtual_memory;
            NtReadVirtualMemory(
                process_handle: ProcessHandle,
                base_address: Platform::RawConstPointer<u8> = *,
                buffer: Platform::RawMutPointer<u8> = *,
                number_of_bytes_to_read: usize,
                number_of_bytes_read: Option<Platform::RawMutPointer<usize>> = *,
            ) => {
                Self::sys_nt_read_virtual_memory(
                    process_handle,
                    base_address,
                    buffer,
                    number_of_bytes_to_read,
                    number_of_bytes_read,
                )
            };
            NtQueryVirtualMemory(
                process_handle: ProcessHandle,
                base_address: usize,
                memory_information_class: u32,
                memory_information: Platform::RawMutPointer<u8> = *,
                memory_information_length: usize,
                return_length: Option<Platform::RawMutPointer<usize>> = *,
            ) => sys_nt_query_virtual_memory;
            NtMapViewOfSection(
                section_handle: Handle,
                process_handle: ProcessHandle,
                base_address: Platform::RawMutPointer<usize> = *,
                zero_bits: usize,
                commit_size: usize,
                section_offset: Option<Platform::RawConstPointer<i64>> = *,
                view_size: Platform::RawMutPointer<usize> = *,
                inherit_disposition: u32,
                allocation_type: u32,
                page_protection: u32,
            ) => sys_nt_map_view_of_section(MapViewOfSectionParameters);
            NtMapViewOfSectionEx(
                section_handle: Handle,
                process_handle: ProcessHandle,
                base_address: Platform::RawMutPointer<usize> = *,
                zero_bits: usize,
                commit_size: usize,
                section_offset: Option<Platform::RawConstPointer<i64>> = *,
                view_size: Platform::RawMutPointer<usize> = *,
                inherit_disposition: u32,
                allocation_type: u32,
                page_protection: u32,
                extended_parameters: Option<Platform::RawConstPointer<u8>> = *,
                extended_parameter_count: u32,
            ) => {
                self.sys_nt_map_view_of_section_ex(
                    MapViewOfSectionParameters {
                        section_handle,
                        process_handle,
                        base_address,
                        zero_bits,
                        commit_size,
                        section_offset,
                        view_size,
                        inherit_disposition,
                        allocation_type,
                        page_protection,
                    },
                    extended_parameters,
                    extended_parameter_count,
                )
            };
            NtUnmapViewOfSection(
                process_handle: ProcessHandle,
                base_address: usize,
            ) => sys_nt_unmap_view_of_section;
            NtUnmapViewOfSectionEx(
                process_handle: ProcessHandle,
                base_address: usize,
                flags: u32,
            ) => sys_nt_unmap_view_of_section_ex;
            NtContinue(
                context: Platform::RawConstPointer<nt_types::X64Context> = *,
                test_alert: bool,
            ) => {
                // A restored context already carries the guest's `rax`, so success must not
                // overwrite it with a status.
                match self.sys_nt_continue(ctx, context, test_alert) {
                    Ok(()) => return true,
                    Err(status) => status,
                }
            };
            NtTerminateProcess(
                process_handle: ProcessHandle,
                exit_status: i32,
            ) => sys_nt_terminate_process;
            NtTerminateThread(
                thread_handle: ThreadHandle,
                exit_status: i32,
            ) => sys_nt_terminate_thread;
            NtTestAlert() => test_alert;
            // TODO: not supported yet
            NtManageHotPatch() => {
                NtStatus::NOT_IMPLEMENTED
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use litebox_common_linux::PtRegs;
    use litebox_common_windows::NtSysno;
    use litebox_common_windows::nt_status::NtStatus;

    use crate::syscalls::Handle;
    use crate::syscalls::event::{EventHandleObject, EventSubsystem};
    use crate::tests::test_task;

    const SENTINEL_RAX: usize = 0x5a5a_5a5a;
    const EVENT_ALL_ACCESS: usize = 0x001f_0003;

    fn regs(sysno: NtSysno) -> PtRegs {
        PtRegs {
            orig_rax: sysno.as_raw() as usize,
            rax: SENTINEL_RAX,
            ..PtRegs::default()
        }
    }

    fn status(ctx: &PtRegs) -> NtStatus {
        NtStatus::from_raw(u32::try_from(ctx.rax).unwrap())
    }

    #[test]
    fn dispatch_decodes_register_arguments_and_stores_status() {
        let task = test_task();
        let mut ctx = regs(NtSysno::NtClose);
        ctx.r10 = Handle::from_raw_fd(1234).unwrap().as_raw();
        assert!(task.dispatch_nt_syscall(&mut ctx));
        assert_eq!(status(&ctx), NtStatus::INVALID_HANDLE);
    }

    #[test]
    fn dispatch_decodes_stack_arguments() {
        let task = test_task();
        let mut handle = Handle::default();
        // The fifth argument (`initial_state`) is the first stack argument, which sits after the
        // return address and the 32-byte shadow space.
        let stack = [0usize, 0, 0, 0, 0, 1];
        let mut ctx = regs(NtSysno::NtCreateEvent);
        ctx.r10 = core::ptr::from_mut(&mut handle) as usize;
        ctx.rdx = EVENT_ALL_ACCESS;
        ctx.r8 = 0;
        ctx.r9 = 0;
        ctx.rsp = stack.as_ptr() as usize;

        assert!(task.dispatch_nt_syscall(&mut ctx));
        assert_eq!(status(&ctx), NtStatus::SUCCESS);
        let signaled = task
            .typed_handle_entry::<EventSubsystem<crate::tests::TestPlatform>>(handle)
            .unwrap()
            .with_entry(EventHandleObject::is_signaled);
        assert!(signaled, "initial_state must be decoded from the stack");
    }

    #[test]
    fn dispatch_decodes_boolean_arguments_from_the_low_byte() {
        let task = test_task();
        let mut handle = Handle::default();
        // `BOOLEAN` is a byte; garbage in the upper bits of the stack slot must be ignored.
        let stack = [0usize, 0, 0, 0, 0, 0x100];
        let mut ctx = regs(NtSysno::NtCreateEvent);
        ctx.r10 = core::ptr::from_mut(&mut handle) as usize;
        ctx.rdx = EVENT_ALL_ACCESS;
        ctx.rsp = stack.as_ptr() as usize;

        assert!(task.dispatch_nt_syscall(&mut ctx));
        assert_eq!(status(&ctx), NtStatus::SUCCESS);
        let signaled = task
            .typed_handle_entry::<EventSubsystem<crate::tests::TestPlatform>>(handle)
            .unwrap()
            .with_entry(EventHandleObject::is_signaled);
        assert!(!signaled);
    }

    #[test]
    fn dispatch_nt_continue_keeps_restored_rax_instead_of_a_status() {
        use zerocopy::FromZeros as _;

        use crate::nt_types::{ContextFlags, X64Context};

        let task = test_task();
        let mut context = X64Context::new_zeroed();
        context.context_flags = (ContextFlags::CONTROL | ContextFlags::INTEGER).bits();
        context.rip = 0x1000;
        context.rsp = 0x2000;
        context.rax = 0x1234;

        let mut ctx = regs(NtSysno::NtContinue);
        ctx.r10 = core::ptr::from_ref(&context) as usize;
        assert!(task.dispatch_nt_syscall(&mut ctx));
        assert_eq!((ctx.rip, ctx.rsp, ctx.rax), (0x1000, 0x2000, 0x1234));

        // A failed restore reports its status like any other syscall.
        let mut ctx = regs(NtSysno::NtContinue);
        assert!(task.dispatch_nt_syscall(&mut ctx));
        assert_eq!(status(&ctx), NtStatus::ACCESS_VIOLATION);
    }

    #[test]
    fn dispatch_rejects_unsupported_and_undecodable_syscalls() {
        let task = test_task();

        let mut ctx = regs(NtSysno::NtRaiseHardError);
        assert!(!task.dispatch_nt_syscall(&mut ctx));
        assert_eq!(ctx.rax, SENTINEL_RAX);

        let mut ctx = PtRegs {
            orig_rax: 0xffff,
            rax: SENTINEL_RAX,
            ..PtRegs::default()
        };
        assert!(!task.dispatch_nt_syscall(&mut ctx));
        assert_eq!(ctx.rax, SENTINEL_RAX);

        // A stack argument whose address overflows cannot be decoded, so no handler runs.
        let mut ctx = regs(NtSysno::NtCreateEvent);
        ctx.rsp = usize::MAX - 8;
        assert!(!task.dispatch_nt_syscall(&mut ctx));
        assert_eq!(ctx.rax, SENTINEL_RAX);
    }
}
