//! Opt-in AMD device bindings for the contained HaloLoom runtime.
//!
//! This does not expose /dev wholesale or change filesystem/network policy.
//! The outer container must already contain exactly the requested devices.
use std::fs;
use std::io;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::path::PathBuf;

use codex_protocol::permissions::FileSystemSandboxPolicy;
use codex_protocol::permissions::ReadDenyMatcher;

const DEVICE_ENV: &str = "HALOLOOM_CODEX_AMD_GPU_DEVICES";

/// Only an actual sandboxed command may consume the operator's GPU request.
/// Internal namespace/proc probes retain their original minimal device tree.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum DeviceRequest {
    #[default]
    Disabled,
    CommandEnvironment,
}

struct DeviceFacts {
    canonical: PathBuf,
    character_device: bool,
    device_number: (u32, u32),
    sysfs_device_number: (u32, u32),
    vendor: Option<u32>,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn render_minor(path: &str) -> Option<u32> {
    let suffix = path.strip_prefix("/dev/dri/renderD")?;
    let minor: u32 = suffix.parse().ok()?;
    (suffix == minor.to_string() && (128..=255).contains(&minor)).then_some(minor)
}

fn inspect_device(path: &Path) -> io::Result<DeviceFacts> {
    let metadata = fs::symlink_metadata(path)?;
    let canonical = fs::canonicalize(path)?;
    let (sysfs_device_number, vendor) = read_sysfs_identity(path, Path::new("/sys"))?;
    Ok(DeviceFacts {
        canonical,
        character_device: metadata.file_type().is_char_device(),
        device_number: (libc::major(metadata.rdev()), libc::minor(metadata.rdev())),
        sysfs_device_number,
        vendor,
    })
}

fn read_sysfs_identity(path: &Path, root: &Path) -> io::Result<((u32, u32), Option<u32>)> {
    let render = path != Path::new("/dev/kfd");
    let sysfs = if render {
        root.join("class/drm").join(
            path.file_name()
                .ok_or_else(|| invalid("missing render name"))?,
        )
    } else {
        root.join("class/kfd/kfd")
    };
    let identity = fs::read_to_string(sysfs.join("dev"))?;
    let (major, minor) = identity
        .trim()
        .split_once(':')
        .ok_or_else(|| invalid("invalid sysfs device identity"))?;
    let sysfs_device_number = (
        major.parse().map_err(|_| invalid("invalid sysfs major"))?,
        minor.parse().map_err(|_| invalid("invalid sysfs minor"))?,
    );
    let vendor = if render {
        let value = fs::read_to_string(sysfs.join("device/vendor"))?;
        Some(
            u32::from_str_radix(value.trim().trim_start_matches("0x"), 16)
                .map_err(|_| invalid("invalid render vendor"))?,
        )
    } else {
        None
    };
    Ok((sysfs_device_number, vendor))
}

fn device_mount_arguments(
    raw: Option<&str>,
    mut inspect: impl FnMut(&Path) -> io::Result<DeviceFacts>,
    mut allowed: impl FnMut(&Path) -> bool,
) -> io::Result<Vec<String>> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    if raw.len() > 256 {
        return Err(invalid("AMD device selector exceeds 256 bytes"));
    }
    let paths: Vec<String> = serde_json::from_str(raw)
        .map_err(|_| invalid("AMD devices must be a JSON array of paths"))?;
    if paths.is_empty() {
        return Ok(Vec::new());
    }
    // Validate the complete syntax before probing devices. Permit only one
    // explicit KFD/render pair; no wildcard, directory, alias or extra node.
    if paths.len() != 2
        || paths
            .iter()
            .filter(|path| path.as_str() == "/dev/kfd")
            .count()
            != 1
        || paths
            .iter()
            .filter(|path| render_minor(path).is_some())
            .count()
            != 1
    {
        return Err(invalid(
            "AMD devices require /dev/kfd and one canonical renderD128..255 path",
        ));
    }
    let mut args = Vec::new();
    for value in paths {
        let path = Path::new(&value);
        if !allowed(path) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "filesystem policy denies requested AMD device",
            ));
        }
        let facts = inspect(path)?;
        if !facts.character_device
            || facts.canonical != path
            || facts.device_number != facts.sysfs_device_number
        {
            return Err(invalid(
                "AMD device must be a canonical character node matching read-only sysfs",
            ));
        }
        if let Some(minor) = render_minor(&value)
            && (facts.vendor != Some(0x1002) || facts.device_number != (226, minor))
        {
            return Err(invalid(
                "requested render node is not the matching AMD DRM device",
            ));
        }
        args.extend(["--dev-bind".to_string(), value.clone(), value]);
    }
    Ok(args)
}

pub(crate) fn configured_device_mount_arguments(
    request: DeviceRequest,
    policy: &FileSystemSandboxPolicy,
    cwd: &Path,
) -> io::Result<Vec<String>> {
    if request == DeviceRequest::Disabled {
        return Ok(Vec::new());
    }
    let raw = match std::env::var(DEVICE_ENV) {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(invalid("AMD device selector is not UTF-8"));
        }
    };
    policy_device_mount_arguments(raw.as_deref(), policy, cwd, inspect_device)
}

fn policy_device_mount_arguments(
    raw: Option<&str>,
    policy: &FileSystemSandboxPolicy,
    cwd: &Path,
    inspect: impl FnMut(&Path) -> io::Result<DeviceFacts>,
) -> io::Result<Vec<String>> {
    let deny = ReadDenyMatcher::try_new_for_local_paths(policy, cwd)
        .map_err(|_| invalid("invalid read-deny policy for AMD device"))?;
    device_mount_arguments(raw, inspect, |path| {
        policy.can_read_local_path_with_cwd(path, cwd)
            && !deny
                .as_ref()
                .is_some_and(|matcher| matcher.is_local_path_read_denied(path))
    })
}

#[cfg(test)]
#[path = "amd_gpu_tests.rs"]
mod tests;
