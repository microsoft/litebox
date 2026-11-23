// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The container's Windows root: the layer folders of containerd's `windows` snapshotter, mounted
//! as hcsshim mounts them for process isolation (`vmcompute.dll`'s undocumented layer API).

use std::fs::{File, OpenOptions};
use std::io::{self, Read as _, Seek as _, Write as _};
use std::os::windows::fs::OpenOptionsExt as _;
use std::os::windows::io::AsRawHandle as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use containerd_shim::protos::types::mount::Mount;
use windows_sys::Win32::Foundation::{
    ERROR_DEVICE_NOT_CONNECTED, ERROR_NOT_READY, ERROR_SHARING_VIOLATION,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_DISPOSITION_INFO, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FileDispositionInfo,
    SetFileInformationByHandle,
};
use windows_sys::core::{GUID, HRESULT, PCWSTR};

use super::security::wide;
use super::{hresult, is, size_u32};
use crate::{Result, invalid, unsupported};

const LAYER_MOUNT: &str = "windows-layer";
/// A JSON array of the parents' folders, topmost first.
const PARENTS_OPTION: &str = "parentLayerPaths=";
/// The scratch's disk, which activating attaches.
const SCRATCH_DISK: &str = "sandbox.vhdx";
/// hcsshim's.
const ATTEMPTS: u32 = 5;
const RETRY_DELAY: Duration = Duration::from_millis(100);
/// `GRAPH_DRIVER_TYPE`'s filter driver.
const FILTER_DRIVER: isize = 1;

#[repr(C)]
struct DriverInfo {
    flavour: isize,
    home_dir: PCWSTR,
}

impl DriverInfo {
    fn new() -> Self {
        let empty: &'static [u16] = &[0];
        Self {
            flavour: FILTER_DRIVER,
            home_dir: empty.as_ptr(),
        }
    }
}

#[repr(C)]
struct LayerDescriptor {
    layer_id: GUID,
    flags: u32,
    path: PCWSTR,
}

// Counts and lengths are pointer-sized, as hcsshim passes them.
#[link(name = "vmcompute", kind = "raw-dylib")]
unsafe extern "system" {
    fn ActivateLayer(info: *const DriverInfo, id: PCWSTR) -> HRESULT;
    fn DeactivateLayer(info: *const DriverInfo, id: PCWSTR) -> HRESULT;
    fn PrepareLayer(
        info: *const DriverInfo,
        id: PCWSTR,
        layers: *const LayerDescriptor,
        count: usize,
    ) -> HRESULT;
    fn UnprepareLayer(info: *const DriverInfo, id: PCWSTR) -> HRESULT;
    fn GetLayerMountPath(
        info: *const DriverInfo,
        id: PCWSTR,
        length: *mut usize,
        buffer: *mut u16,
    ) -> HRESULT;
    fn NameToGuid(name: PCWSTR, guid: *mut GUID) -> HRESULT;
}

/// The layer folders of containerd's root mounts: the parents, topmost first, then the scratch.
pub fn folders(mounts: &[Mount]) -> Result<Vec<PathBuf>> {
    let [mount] = mounts else {
        return Err(unsupported(format!(
            "{} root mounts: the container's root must be one {LAYER_MOUNT} mount, as containerd's \
             windows snapshotter makes",
            mounts.len()
        )));
    };
    if mount.type_ != LAYER_MOUNT {
        return Err(unsupported(format!(
            "{:?} root mounts are not supported: use containerd's windows snapshotter",
            mount.type_
        )));
    }
    let mut folders = Vec::new();
    for option in &mount.options {
        if option == "ro" {
            return Err(unsupported("a read-only Windows root is not supported"));
        }
        if let Some(parents) = option.strip_prefix(PARENTS_OPTION) {
            folders = serde_json::from_str(parents)
                .map_err(|error| invalid(format!("invalid {PARENTS_OPTION}: {error}")))?;
        }
    }
    folders.push(PathBuf::from(&mount.source));
    Ok(folders)
}

/// `folders` as [`folders`] gives them, or as the spec's `windows.layerFolders`.
pub fn check(folders: &[PathBuf]) -> Result<()> {
    if folders.len() < 2 {
        return Err(crate::error(
            crate::ttrpc::Code::FAILED_PRECONDITION,
            "the container needs a Windows root for the broker, such as \
             mcr.microsoft.com/windows/nanoserver:ltsc2025: run it with containerd's windows \
             snapshotter, or give the spec's windows.layerFolders",
        ));
    }
    if let Some(relative) = folders.iter().find(|folder| !folder.is_absolute()) {
        return Err(invalid(format!(
            "the layer folder {} is not absolute",
            relative.display()
        )));
    }
    Ok(())
}

/// The record of a container's layers. It names the scratch layer from before they mount until
/// they unmount, so that whoever takes it next finds what a killed daemon or a failed unmount left
/// mounted. Taking it is opening it exclusively, and only its holder may mount or unmount the
/// layers, or stop the container that uses them: a same-ID container's cleanup may still run.
/// Dropped while it names no layers, it is removed.
pub struct Record {
    file: File,
    scratch: Option<PathBuf>,
}

impl Record {
    /// Takes the record at `path`, creating it if missing; `None` while another holds it.
    pub fn claim(path: &Path) -> io::Result<Option<Self>> {
        Self::take(OpenOptions::new().create(true), path)
    }

    /// Takes the record at `path`; `None` if it is missing or another holds it.
    pub fn open(path: &Path) -> io::Result<Option<Self>> {
        match Self::take(&mut OpenOptions::new(), path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            taken => taken,
        }
    }

    fn take(options: &mut OpenOptions, path: &Path) -> io::Result<Option<Self>> {
        let opened = options
            .read(true)
            .write(true)
            .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE)
            .share_mode(0)
            .open(path);
        let mut file = match opened {
            Err(error) if is(&error, ERROR_SHARING_VIOLATION) => return Ok(None),
            opened => opened?,
        };
        let mut scratch = String::new();
        file.read_to_string(&mut scratch)?;
        let scratch = (!scratch.is_empty()).then(|| PathBuf::from(scratch));
        Ok(Some(Self { file, scratch }))
    }

    pub fn names_layers(&self) -> bool {
        self.scratch.is_some()
    }

    /// Unmounts the layers it names, maybe mounted by another process. A scratch whose disk is not
    /// attached is not mounted, so this can be retried.
    pub fn unmount(&mut self) -> io::Result<()> {
        if let Some(scratch) = &self.scratch {
            release(scratch)?;
        }
        self.write(None)
    }

    fn write(&mut self, scratch: Option<&Path>) -> io::Result<()> {
        self.file.set_len(0)?;
        self.file.rewind()?;
        if let Some(scratch) = scratch {
            self.file.write_all(scratch.to_string_lossy().as_bytes())?;
        }
        self.scratch = scratch.map(Path::to_owned);
        Ok(())
    }
}

impl Drop for Record {
    fn drop(&mut self) {
        if self.names_layers() {
            return;
        }
        let information = FILE_DISPOSITION_INFO { DeleteFile: true };
        // SAFETY: `file` is open with `DELETE`, and `information` outlives the call, which only
        // reads it.
        let deleted = unsafe {
            SetFileInformationByHandle(
                self.file.as_raw_handle(),
                FileDispositionInfo,
                (&raw const information).cast(),
                size_u32::<FILE_DISPOSITION_INFO>(),
            )
        };
        if deleted == 0 {
            log::warn!(
                "cannot remove the layers' record: {}",
                io::Error::last_os_error()
            );
        }
    }
}

/// The layers as mounted for a container until dropped, which unmounts them.
pub struct Mounted {
    scratch: PathBuf,
    record: Record,
    /// `{Id, Path}`, the HCS schema's `Layer`, of each parent.
    parents: Vec<serde_json::Value>,
    volume: String,
}

impl Mounted {
    /// The HCS schema's `Storage` of a process-isolated container.
    pub fn storage(&self) -> serde_json::Value {
        serde_json::json!({"Layers": self.parents, "Path": self.volume})
    }
}

impl Drop for Mounted {
    fn drop(&mut self) {
        let unmounted =
            unmount_wide(&wide(self.scratch.as_os_str())).and_then(|()| self.record.write(None));
        if let Err(error) = unmounted {
            log::error!(
                "cannot unmount the container's layers, left to the delete action: {error}"
            );
        }
    }
}

/// `folders` must be [`check`]ed.
pub fn mount(folders: &[PathBuf], mut record: Record) -> io::Result<Mounted> {
    let (scratch, parents) = folders.split_last().expect("checked: two folders at least");
    let parents: Vec<(GUID, Vec<u16>)> = parents
        .iter()
        .map(|folder| Ok((layer_guid(folder)?, wide(folder.as_os_str()))))
        .collect::<io::Result<_>>()?;
    let descriptors: Vec<LayerDescriptor> = parents
        .iter()
        .map(|(id, path)| LayerDescriptor {
            layer_id: *id,
            flags: 0,
            path: path.as_ptr(),
        })
        .collect();
    // Before mounting: the mount outlives a killed daemon.
    record.write(Some(scratch))?;
    let id = wide(scratch.as_os_str());
    let info = DriverInfo::new();
    if let Err(error) = activate(&info, &id, &descriptors) {
        if let Err(error) = record.unmount() {
            log::error!(
                "cannot unmount the container's layers, left to the delete action: {error}"
            );
        }
        return Err(error);
    }
    let mut mounted = Mounted {
        scratch: scratch.clone(),
        record,
        parents: Vec::new(),
        volume: String::new(),
    };
    mounted.volume = mount_path(&info, &id)?;
    if !mounted.volume.ends_with('\\') {
        mounted.volume.push('\\');
    }
    mounted.parents = (folders.iter().zip(&parents))
        .map(|(folder, (id, _))| serde_json::json!({"Id": guid_string(id), "Path": folder}))
        .collect();
    Ok(mounted)
}

fn release(scratch: &Path) -> io::Result<()> {
    // Attached, the disk is open; nothing else opens it.
    match OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(scratch.join(SCRATCH_DISK))
    {
        Err(error) if is(&error, ERROR_SHARING_VIOLATION) => {
            unmount_wide(&wide(scratch.as_os_str()))
        }
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

/// hcsshim's retries: a host may report a layer's volume before it is ready.
fn activate(info: &DriverInfo, id: &[u16], descriptors: &[LayerDescriptor]) -> io::Result<()> {
    let mut attempt = 1;
    loop {
        match activate_and_prepare(info, id, descriptors) {
            Err(error)
                if attempt < ATTEMPTS
                    && (is(&error, ERROR_NOT_READY) || is(&error, ERROR_DEVICE_NOT_CONNECTED)) =>
            {
                log::warn!("retrying to mount the layers: {error}");
                std::thread::sleep(RETRY_DELAY);
                attempt += 1;
            }
            result => return result,
        }
    }
}

fn activate_and_prepare(
    info: &DriverInfo,
    id: &[u16],
    descriptors: &[LayerDescriptor],
) -> io::Result<()> {
    // SAFETY: `info` and the NUL-terminated `id` outlive the call.
    hresult(unsafe { ActivateLayer(info, id.as_ptr()) })?;
    // SAFETY: as above; the descriptors and the paths they point to outlive the call.
    let prepared = hresult(unsafe {
        PrepareLayer(info, id.as_ptr(), descriptors.as_ptr(), descriptors.len())
    });
    if prepared.is_err() {
        // SAFETY: as for `ActivateLayer`.
        unsafe { DeactivateLayer(info, id.as_ptr()) };
    }
    prepared
}

fn mount_path(info: &DriverInfo, id: &[u16]) -> io::Result<String> {
    let mut length = 0;
    // SAFETY: `info`, the NUL-terminated `id` and `length` outlive the call, which writes only
    // `length` without a buffer.
    hresult(unsafe {
        GetLayerMountPath(info, id.as_ptr(), &raw mut length, std::ptr::null_mut())
    })?;
    let mut path = vec![0u16; length];
    if length > 0 {
        // SAFETY: as above, and `path` holds the `length` units that the call may write.
        hresult(unsafe {
            GetLayerMountPath(info, id.as_ptr(), &raw mut length, path.as_mut_ptr())
        })?;
    }
    let end = path
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(path.len());
    String::from_utf16(&path[..end]).map_err(io::Error::other)
}

/// Deactivating detaches the disk, the filter with it, so it alone decides: unpreparing may fail
/// on a scratch that an interrupted unmount unprepared already.
fn unmount_wide(id: &[u16]) -> io::Result<()> {
    let info = DriverInfo::new();
    // SAFETY: `info` and the NUL-terminated `id` outlive the calls.
    let unprepared = hresult(unsafe { UnprepareLayer(&raw const info, id.as_ptr()) });
    // SAFETY: as above.
    let deactivated = hresult(unsafe { DeactivateLayer(&raw const info, id.as_ptr()) });
    if let Err(error) = unprepared {
        log::warn!("cannot unprepare the layers: {error}");
    }
    deactivated
}

/// The ID that HCS and the filter know a layer by, from its folder's name.
fn layer_guid(folder: &Path) -> io::Result<GUID> {
    let name = folder.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("the layer folder {} has no name", folder.display()),
        )
    })?;
    let mut guid = GUID::from_u128(0);
    // SAFETY: the NUL-terminated name and `guid` outlive the call, which writes only `guid`.
    hresult(unsafe { NameToGuid(wide(name).as_ptr(), &raw mut guid) })?;
    Ok(guid)
}

/// As Go's `guid.GUID.String`, which HCS documents carry.
fn guid_string(guid: &GUID) -> String {
    let [high, low, node @ ..] = guid.data4;
    let node = node
        .iter()
        .fold(0_u64, |node, &byte| node << 8 | u64::from(byte));
    format!(
        "{:08x}-{:04x}-{:04x}-{high:02x}{low:02x}-{node:012x}",
        guid.data1, guid.data2, guid.data3
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layer_mount(source: &str, options: &[&str]) -> Mount {
        Mount {
            type_: LAYER_MOUNT.to_owned(),
            source: source.to_owned(),
            options: options.iter().map(|&option| option.to_owned()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn the_scratch_follows_its_parents() {
        let parents = r#"parentLayerPaths=["C:\\s\\2","C:\\s\\1"]"#;
        let mount = layer_mount(r"C:\s\3", &["rw", parents, "unknown"]);
        let folders = folders(&[mount]).unwrap();
        let want = [r"C:\s\2", r"C:\s\1", r"C:\s\3"].map(PathBuf::from);
        assert_eq!(folders, want);
        check(&folders).unwrap();
    }

    #[test]
    fn other_roots_are_refused() {
        let layer = layer_mount(r"C:\s\3", &[]);
        let mut bind = layer.clone();
        bind.type_ = "bind".to_owned();
        let refused: [&[Mount]; 4] = [
            &[],
            &[layer.clone(), layer],
            &[bind],
            &[layer_mount(r"C:\s\3", &["ro"])],
        ];
        for mounts in refused {
            assert!(folders(mounts).is_err(), "{mounts:?}");
        }
        assert!(folders(&[layer_mount(r"C:\s\3", &["parentLayerPaths=["])]).is_err());
        assert!(check(&[PathBuf::from(r"C:\s\3")]).is_err(), "no parent");
        let relative = [PathBuf::from("s"), PathBuf::from(r"C:\s\3")];
        assert!(check(&relative).is_err(), "a relative folder");
    }

    #[test]
    fn a_record_of_layers_that_are_not_mounted_is_removed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("record");
        assert!(Record::open(&path).unwrap().is_none(), "no record");
        let scratch = dir.path().join("scratch");
        std::fs::create_dir(&scratch).unwrap();
        std::fs::write(&path, scratch.to_str().unwrap()).unwrap();
        let mut record = Record::open(&path).unwrap().expect("a record");
        assert!(Record::open(&path).unwrap().is_none(), "held");
        assert!(Record::claim(&path).unwrap().is_none(), "held");
        record.unmount().unwrap();
        drop(record);
        assert!(!path.exists(), "a scratch without its disk");
        std::fs::write(scratch.join(SCRATCH_DISK), b"").unwrap();
        std::fs::write(&path, scratch.to_str().unwrap()).unwrap();
        drop(Record::open(&path).unwrap());
        assert!(path.exists(), "still names layers");
        Record::open(&path).unwrap().unwrap().unmount().unwrap();
        assert!(!path.exists(), "a detached disk");
        drop(Record::claim(&path).unwrap().expect("a new record"));
        assert!(!path.exists(), "names nothing");
    }

    #[test]
    fn a_layer_id_is_its_folder_names_guid() {
        // As runhcs gave containerd's first snapshot.
        let id = layer_guid(Path::new(r"C:\snapshots\1")).unwrap();
        assert_eq!(guid_string(&id), "65ed1907-894d-50ff-bdcb-cc63fb515966");
    }
}
