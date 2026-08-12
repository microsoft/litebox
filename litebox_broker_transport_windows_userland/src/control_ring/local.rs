// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::io::{Error, ErrorKind, Result as IoResult};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use litebox_broker_protocol::message::{BrokerNotification, BrokerRequest, BrokerResponse};
use litebox_broker_protocol::wire::{decode_notification, decode_response, encode_request};
use litebox_broker_transport::channel::{LocalCallChannel, LocalNotificationChannel};
use litebox_broker_transport::control_ring::{
    CONTROL_RING_READY, ControlRing, ControlRingConsumer, ControlRingProducer,
    ControlRingReadError, ControlRingReadStatus, ControlRingWakeHandle, ControlRingWriteStatus,
};

use crate::named_pipe::WindowsNamedPipeStream;
use crate::pending_calls::{PendingCalls, pending_calls_error};
use crate::setup::{
    copy_io_error, invalid_data, read_frame, read_pipe_until_cancelled, ring_error, wire_error,
    write_frame,
};
use crate::shared_memory::WindowsSharedMemory;

use super::{PipeLiveness, file_handle};

/// Call-issuing endpoint of an active local control-ring association.
pub struct WindowsControlRingLocalCallChannel {
    association: Arc<LocalRingAssociation>,
}

/// Local notification receiver for a shared-ring Windows broker association.
pub struct WindowsControlRingLocalNotificationChannel {
    consumer: ControlRingConsumer<WindowsSharedMemory>,
    association: Arc<LocalRingAssociation>,
}

struct LocalRingAssociation {
    request_producer: Mutex<ControlRingProducer<WindowsSharedMemory>>,
    pending_calls: Arc<PendingCalls>,
    liveness: PipeLiveness,
    request_wake: ControlRingWakeHandle<WindowsSharedMemory>,
    response_wake: ControlRingWakeHandle<WindowsSharedMemory>,
    notification_wake: ControlRingWakeHandle<WindowsSharedMemory>,
}

pub(crate) fn activate_local(
    stream: WindowsNamedPipeStream,
    negotiated: bool,
    setup_deadline: Option<Instant>,
    ring: ControlRing<WindowsSharedMemory>,
) -> IoResult<(
    WindowsControlRingLocalCallChannel,
    WindowsControlRingLocalNotificationChannel,
)> {
    if !negotiated {
        return Err(invalid_data(
            "broker local setup channel activated before negotiation completed",
        ));
    }
    write_frame(file_handle(&stream), CONTROL_RING_READY, setup_deadline)?;
    let ready = read_frame(file_handle(&stream), setup_deadline)?.ok_or_else(|| {
        Error::new(
            ErrorKind::UnexpectedEof,
            "broker closed before control-ring setup acknowledgement",
        )
    })?;
    if ready != CONTROL_RING_READY {
        return Err(invalid_data(
            "broker sent an invalid control-ring setup acknowledgement",
        ));
    }

    let litebox_broker_transport::control_ring::LocalControlRingEndpoints {
        request_producer,
        response_consumer,
        notification_consumer,
    } = ring.into_local();
    let pending_calls = Arc::new(PendingCalls::new());
    let stream = Arc::new(stream);
    let association = Arc::new(LocalRingAssociation {
        liveness: PipeLiveness::new(Arc::clone(&stream), false)?,
        request_wake: request_producer.wake_handle(),
        request_producer: Mutex::new(request_producer),
        response_wake: response_consumer.wake_handle(),
        notification_wake: notification_consumer.wake_handle(),
        pending_calls,
    });
    let response_association = Arc::clone(&association);
    thread::Builder::new()
        .name("litebox-broker-responses".to_owned())
        .spawn(move || dispatch_responses(response_consumer, response_association))?;
    let monitor_association = Arc::clone(&association);
    thread::Builder::new()
        .name("litebox-broker-liveness".to_owned())
        .spawn(move || monitor_local_pipe(&stream, &monitor_association))?;
    Ok((
        WindowsControlRingLocalCallChannel {
            association: Arc::clone(&association),
        },
        WindowsControlRingLocalNotificationChannel {
            consumer: notification_consumer,
            association,
        },
    ))
}

impl LocalCallChannel for WindowsControlRingLocalCallChannel {
    type Error = Error;

    fn call(&self, request: BrokerRequest) -> IoResult<BrokerResponse> {
        let association = &self.association;
        let request_id = request.request_id;
        let pending_call = association
            .pending_calls
            .register(request_id)
            .map_err(pending_calls_error)?;
        let frame = encode_request(request);
        let write_result = {
            let mut producer = association
                .request_producer
                .lock()
                .map_err(|_| Error::other("broker request writer mutex poisoned"))?;
            loop {
                let status = association
                    .pending_calls
                    .run_if_live(|| producer.try_write(&frame).map_err(ring_error))
                    .map_err(pending_calls_error);
                match status {
                    Ok(ControlRingWriteStatus::Written) => {
                        break producer.wake_consumer();
                    }
                    Ok(ControlRingWriteStatus::Full { wait_epoch }) => {
                        if let Err(error) = producer.wait_for_capacity(wait_epoch) {
                            break Err(error);
                        }
                    }
                    Err(error) => break Err(error),
                }
            }
        };
        if let Err(error) = write_result {
            let _ = association.fail(error);
        }
        pending_call.wait().map_err(|error| copy_io_error(&error))
    }
}

impl Drop for WindowsControlRingLocalCallChannel {
    fn drop(&mut self) {
        let _ = self.association.fail(Error::new(
            ErrorKind::ConnectionAborted,
            "broker local call channel dropped",
        ));
    }
}

impl LocalNotificationChannel for WindowsControlRingLocalNotificationChannel {
    type Error = Error;

    fn recv_notification(&mut self) -> IoResult<Option<BrokerNotification>> {
        loop {
            if let Some(error) = self.association.pending_calls.current_failure() {
                return Err(copy_io_error(&error));
            }
            match self.consumer.try_read(decode_notification) {
                Ok(ControlRingReadStatus::Message(notification)) => {
                    self.association
                        .acknowledge_notification(&mut self.consumer)?;
                    return Ok(Some(notification));
                }
                Ok(ControlRingReadStatus::Empty { wait_epoch }) => {
                    if let Some(error) = self.association.pending_calls.current_failure() {
                        return Err(copy_io_error(&error));
                    }
                    if let Err(error) = self.consumer.wait_for_message(wait_epoch) {
                        let result = Err(copy_io_error(&error));
                        let _ = self.association.fail(error);
                        return result;
                    }
                }
                Err(ControlRingReadError::Ring(error)) => {
                    let error = ring_error(error);
                    let result = Err(copy_io_error(&error));
                    let _ = self.association.fail(error);
                    return result;
                }
                Err(ControlRingReadError::Decode(error)) => {
                    let error = wire_error(error);
                    let result = Err(copy_io_error(&error));
                    let _ = self.association.fail(error);
                    return result;
                }
            }
        }
    }
}

impl LocalRingAssociation {
    fn acknowledge_notification(
        &self,
        consumer: &mut ControlRingConsumer<WindowsSharedMemory>,
    ) -> IoResult<()> {
        let result = self
            .pending_calls
            .run_if_live(|| {
                consumer
                    .publish_head()
                    .map_err(ring_error)
                    .and_then(|()| consumer.wake_producer())
            })
            .map_err(pending_calls_error);
        if let Err(error) = result {
            let result = Err(copy_io_error(&error));
            let _ = self.fail(error);
            return result;
        }
        Ok(())
    }

    fn fail(&self, error: Error) -> IoResult<()> {
        self.pending_calls.record_failure(Arc::new(error));
        self.request_wake
            .interrupt_wait()
            .and(self.response_wake.interrupt_wait())
            .and(self.notification_wake.interrupt_wait())
            .and(self.liveness.shutdown())
    }
}

fn dispatch_responses(
    mut consumer: ControlRingConsumer<WindowsSharedMemory>,
    association: Arc<LocalRingAssociation>,
) {
    loop {
        match consumer.try_read(decode_response) {
            Ok(ControlRingReadStatus::Message(response)) => {
                if let Err(error) = consumer
                    .publish_head()
                    .map_err(ring_error)
                    .and_then(|()| consumer.wake_producer())
                    .and_then(|()| {
                        association
                            .pending_calls
                            .complete(response)
                            .map_err(pending_calls_error)
                    })
                {
                    let _ = association.fail(error);
                    return;
                }
            }
            Ok(ControlRingReadStatus::Empty { wait_epoch }) => {
                if association.pending_calls.current_failure().is_some() {
                    return;
                }
                if let Err(error) = consumer.wait_for_message(wait_epoch) {
                    let _ = association.fail(error);
                    return;
                }
            }
            Err(ControlRingReadError::Ring(error)) => {
                let _ = association.fail(ring_error(error));
                return;
            }
            Err(ControlRingReadError::Decode(error)) => {
                let _ = association.fail(wire_error(error));
                return;
            }
        }
    }
}

fn monitor_local_pipe(stream: &WindowsNamedPipeStream, association: &LocalRingAssociation) {
    let mut byte = [0];
    let error = match read_pipe_until_cancelled(
        file_handle(stream),
        &mut byte,
        association.liveness.shutdown_event.handle(),
    ) {
        Ok(0) => Error::new(
            ErrorKind::UnexpectedEof,
            "broker closed the active association",
        ),
        Ok(_) => invalid_data("broker sent unexpected active control-pipe data"),
        Err(error) if error.kind() == ErrorKind::ConnectionAborted => return,
        Err(error) => error,
    };
    let _ = association.fail(error);
}
