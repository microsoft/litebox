// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Network namespaces and their endpoints, through the Host Compute Network service
//! (`computenetwork.dll`).

use std::ffi::{OsStr, c_void};
use std::io;
use std::mem::DropGuard;
use std::net::IpAddr;
use std::ptr::null_mut;

use serde_json::Value;
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::HostComputeNetwork::{
    HcnCloseEndpoint, HcnCloseNamespace, HcnOpenEndpoint, HcnOpenNamespace,
    HcnQueryEndpointProperties, HcnQueryNamespaceProperties,
};
use windows_sys::core::{GUID, HRESULT, PCWSTR, PWSTR};

use super::super::security::{from_wide, wide};
use super::Error;
use crate::rootfs::Dns;
use crate::spec::Guid;

/// Schema 2.0 documents, as hcsshim's `hcn` package asks for them.
const QUERY: &str = r#"{"SchemaVersion":{"Major":2,"Minor":0},"Flags":0}"#;

type Open = unsafe extern "system" fn(*const GUID, *mut *mut c_void, *mut PWSTR) -> HRESULT;
type Query = unsafe extern "system" fn(*const c_void, PCWSTR, *mut PWSTR, *mut PWSTR) -> HRESULT;
type Close = unsafe extern "system" fn(*const c_void) -> HRESULT;

#[derive(Debug, Clone, Copy)]
enum Object {
    Namespace(Guid),
    Endpoint(Guid),
}

/// The DNS settings of the endpoints in `namespace`, merged.
pub fn dns(namespace: Guid) -> io::Result<Dns> {
    let namespace = query(Object::Namespace(namespace))?;
    let mut endpoints = Vec::new();
    for resource in array(&namespace, "Resources") {
        if field(resource, "Type").and_then(Value::as_str) != Some("Endpoint") {
            continue;
        }
        let id = (field(resource, "Data").and_then(|data| field(data, "ID")))
            .and_then(Value::as_str)
            .ok_or_else(|| io::Error::other(format!("an endpoint without an ID: {resource}")))?;
        let id = id
            .parse()
            .map_err(|error| io::Error::other(format!("an endpoint's ID {id:?}: {error}")))?;
        endpoints.push(query(Object::Endpoint(id))?);
    }
    Ok(merge(&endpoints))
}

/// An endpoint's domain is its search list unless it has one, as in `resolv.conf`. A server that
/// is not an IP address is skipped, as resolvers skip it.
fn merge(endpoints: &[Value]) -> Dns {
    let mut merged = Dns::default();
    for dns in endpoints
        .iter()
        .filter_map(|endpoint| field(endpoint, "Dns"))
    {
        let own: Vec<&str> = array(dns, "Search").filter_map(Value::as_str).collect();
        if own.is_empty() {
            add(
                &mut merged.search,
                field(dns, "Domain").and_then(Value::as_str),
            );
        }
        add(&mut merged.search, own);
        add(
            &mut merged.options,
            array(dns, "Options").filter_map(Value::as_str),
        );
        for server in array(dns, "ServerList").filter_map(Value::as_str) {
            if let Ok(server) = server.parse::<IpAddr>()
                && !merged.servers.contains(&server)
            {
                merged.servers.push(server);
            }
        }
    }
    merged
}

/// Skips a word with spaces, which would end up as several.
fn add<'v>(list: &mut Vec<String>, words: impl IntoIterator<Item = &'v str>) {
    for word in words {
        if !word.is_empty()
            && !word.contains(char::is_whitespace)
            && !list.iter().any(|kept| kept == word)
        {
            list.push(word.to_owned());
        }
    }
}

fn array<'v>(value: &'v Value, name: &str) -> impl Iterator<Item = &'v Value> {
    (field(value, name).and_then(Value::as_array))
        .into_iter()
        .flatten()
}

/// In any case, as hcsshim's decoder (Go's) reads them: HCN documents its `ID`s as `Id`.
fn field<'v>(value: &'v Value, name: &str) -> Option<&'v Value> {
    let object = value.as_object()?;
    let mut fields = object.iter();
    fields
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value)
}

fn query(object: Object) -> io::Result<Value> {
    let (id, open, read, close): (Guid, Open, Query, Close) = match object {
        Object::Namespace(id) => (
            id,
            HcnOpenNamespace,
            HcnQueryNamespaceProperties,
            HcnCloseNamespace,
        ),
        Object::Endpoint(id) => (
            id,
            HcnOpenEndpoint,
            HcnQueryEndpointProperties,
            HcnCloseEndpoint,
        ),
    };
    let guid = GUID::from_u128(id.0);
    let (mut handle, mut record) = (null_mut(), null_mut());
    // SAFETY: `guid`, `handle` and `record` outlive the call.
    let code = unsafe { open(&raw const guid, &raw mut handle, &raw mut record) };
    // SAFETY: HCN gives the caller its error record, if any.
    unsafe { check(code, record) }?;
    let handle = DropGuard::new(handle, |handle| {
        // SAFETY: the object is open, and `close` is its kind's.
        unsafe { close(handle) };
    });
    let text = wide(OsStr::new(QUERY));
    let (mut properties, mut record) = (null_mut(), null_mut());
    // SAFETY: the object is open, and the NUL-terminated query, `properties` and `record` outlive
    // the call.
    let code = unsafe { read(*handle, text.as_ptr(), &raw mut properties, &raw mut record) };
    // SAFETY: HCN gives the caller its error record, if any.
    unsafe { check(code, record) }?;
    // SAFETY: HCN gives the caller its document on success.
    let properties = unsafe { take(properties) };
    serde_json::from_str(&properties).map_err(|error| {
        io::Error::other(format!(
            "HCN's document {properties:?} is not JSON: {error}"
        ))
    })
}

/// # Safety
///
/// `record` is null, or a NUL-terminated string that HCN allocated for the caller.
unsafe fn check(code: HRESULT, record: PWSTR) -> Result<(), Error> {
    // SAFETY: the caller's.
    let document = unsafe { take(record) };
    // As hcsshim's `checkForErrors`: HCN may report a failure in the record alone.
    if code < 0 || !document.is_empty() {
        return Err(Error { code, document });
    }
    Ok(())
}

/// # Safety
///
/// As [`check`]'s `record`.
unsafe fn take(text: PWSTR) -> String {
    if text.is_null() {
        return String::new();
    }
    // SAFETY: the caller's.
    unsafe {
        let string = from_wide(text);
        CoTaskMemFree(text.cast());
        string
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn the_endpoints_dns_settings_are_merged() {
        let endpoints = [
            json!({"Dns": {"Domain": "d.example", "ServerList": ["192.0.2.1", "192.0.2.2"]}}),
            json!({"Name": "no DNS"}),
            json!({"dns": {
                "Domain": "ignored.example",
                "search": ["s.example", "d.example", "two words"],
                "ServerList": ["192.0.2.2", "dns.example", "192.0.2.3"],
                "Options": ["ndots:5"],
            }}),
        ];
        let expected = Dns {
            search: vec!["d.example".to_owned(), "s.example".to_owned()],
            servers: (["192.0.2.1", "192.0.2.2", "192.0.2.3"].iter())
                .map(|ip| ip.parse().unwrap())
                .collect(),
            options: vec!["ndots:5".to_owned()],
        };
        assert_eq!(merge(&endpoints), expected);
    }
}
