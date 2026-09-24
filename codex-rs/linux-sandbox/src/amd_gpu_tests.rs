use super::*;
use pretty_assertions::assert_eq;

fn observed(path: &Path) -> io::Result<DeviceFacts> {
    let render = path == Path::new("/dev/dri/renderD128");
    Ok(DeviceFacts {
        canonical: path.to_path_buf(),
        character_device: true,
        device_number: if render { (226, 128) } else { (235, 0) },
        sysfs_device_number: if render { (226, 128) } else { (235, 0) },
        vendor: if render { Some(0x1002) } else { None },
    })
}

#[test]
fn disabled_policy_does_not_inspect_devices() {
    for raw in [None, Some("[]")] {
        let mounts = device_mount_arguments(
            raw,
            |_| panic!("device inspection while disabled"),
            |_| true,
        )
        .unwrap();
        assert_eq!(mounts, Vec::<String>::new());
    }
}

#[test]
fn explicit_amd_pair_mounts_only_the_selected_character_devices() {
    let mounts = device_mount_arguments(
        Some(r#"["/dev/kfd","/dev/dri/renderD128"]"#),
        observed,
        |_| true,
    )
    .unwrap();
    assert_eq!(
        mounts,
        vec![
            "--dev-bind",
            "/dev/kfd",
            "/dev/kfd",
            "--dev-bind",
            "/dev/dri/renderD128",
            "/dev/dri/renderD128"
        ]
    );
}

#[test]
fn malformed_or_overbroad_requests_fail_before_device_inspection() {
    for raw in [
        "",
        "true",
        "null",
        "{}",
        "not JSON",
        r#"["/dev"]"#,
        r#"["/dev/kfd"]"#,
        r#"["/dev/kfd","/dev/nvidia0"]"#,
        r#"["/dev/kfd","/dev/dri"]"#,
        r#"["/dev/kfd","/dev/dri/renderD0128"]"#,
        r#"["/dev/kfd","/dev/dri/../nvidia0"]"#,
        r#"["/dev/kfd","/dev/dri/renderD128","/dev/dri/renderD129"]"#,
        r#"["/dev/kfd","/dev/kfd"]"#,
    ] {
        assert!(
            device_mount_arguments(
                Some(raw),
                |_| panic!("inspect malformed allowlist {raw}"),
                |_| true
            )
            .is_err(),
            "accepted {raw}"
        );
    }
}

#[test]
fn explicit_filesystem_denials_are_not_overridden() {
    let result = device_mount_arguments(
        Some(r#"["/dev/kfd","/dev/dri/renderD128"]"#),
        observed,
        |path| path != Path::new("/dev/dri/renderD128"),
    );
    assert!(result.is_err());
}

#[test]
fn non_character_devices_fail_closed() {
    let result = device_mount_arguments(
        Some(r#"["/dev/kfd","/dev/dri/renderD128"]"#),
        |path| {
            let mut facts = observed(path)?;
            facts.character_device = false;
            Ok(facts)
        },
        |_| true,
    );
    assert!(result.is_err());
}

#[test]
fn symlink_or_alias_device_paths_fail_closed() {
    let result = device_mount_arguments(
        Some(r#"["/dev/kfd","/dev/dri/renderD128"]"#),
        |path| {
            let mut facts = observed(path)?;
            facts.canonical = PathBuf::from("/dev/nvidia0");
            Ok(facts)
        },
        |_| true,
    );
    assert!(result.is_err());
}

#[test]
fn nvidia_or_missing_vendor_cannot_pass_as_an_amd_render_node() {
    for vendor in [Some(0x10de), None] {
        let result = device_mount_arguments(
            Some(r#"["/dev/kfd","/dev/dri/renderD128"]"#),
            |path| {
                let mut facts = observed(path)?;
                if path == Path::new("/dev/dri/renderD128") {
                    facts.vendor = vendor;
                }
                Ok(facts)
            },
            |_| true,
        );
        assert!(result.is_err());
    }
}

#[test]
fn device_identity_must_match_the_read_only_sysfs_identity() {
    let result = device_mount_arguments(
        Some(r#"["/dev/kfd","/dev/dri/renderD128"]"#),
        |path| {
            let mut facts = observed(path)?;
            facts.device_number = (1, 1);
            Ok(facts)
        },
        |_| true,
    );
    assert!(result.is_err());
}

#[test]
fn missing_device_or_sysfs_metadata_is_an_error() {
    let result = device_mount_arguments(
        Some(r#"["/dev/kfd","/dev/dri/renderD128"]"#),
        |_| Err(io::Error::from(io::ErrorKind::NotFound)),
        |_| true,
    );
    assert!(result.is_err());
}

#[test]
fn native_wire_profile_keeps_device_reads_and_enforces_denials() {
    // Captured from the real CLI's --permission-profile boundary, not a mock
    // spelling of the adapter's intended profile.
    let raw: serde_json::Value = serde_json::from_str(r#"{"type":"restricted","entries":[{"path":{"type":"path","path":"/"},"access":"read"},{"path":{"type":"path","path":"/tmp/kf-hooks-1ktcdx49/miopen-cache"},"access":"write"},{"path":{"type":"path","path":"/tmp/kf-hooks-1ktcdx49/miopen-db"},"access":"write"},{"path":{"type":"path","path":"/tmp/kf-hooks-1ktcdx49/tmp"},"access":"write"},{"path":{"type":"path","path":"/tmp/kf-hooks-1ktcdx49/torch-extensions"},"access":"write"},{"path":{"type":"path","path":"/tmp/kf-hooks-1ktcdx49/triton"},"access":"write"},{"path":{"type":"path","path":"/workspace/amd-device-policy"},"access":"write"},{"path":{"type":"path","path":"/workspace/amd-device-policy/.git"},"access":"read"},{"path":{"type":"path","path":"/workspace/amd-device-policy/forge_driver.py"},"access":"read"}]}"#).unwrap();
    let profile: codex_protocol::models::PermissionProfile = serde_json::from_value(
        serde_json::json!({"type":"managed", "file_system":raw, "network":"restricted"}),
    )
    .unwrap();
    let (policy, _) = profile.to_runtime_permissions();
    let cwd = Path::new("/workspace/amd-device-policy");
    let selector = Some(r#"["/dev/kfd","/dev/dri/renderD128"]"#);
    let result =
        policy_device_mount_arguments(selector, &policy, cwd, observed).unwrap_or_else(|error| {
            panic!(
                "captured native profile rejected: {error}; full_read={}; policy={policy:?}",
                policy.has_full_disk_read_access()
            )
        });
    assert_eq!(
        result,
        vec![
            "--dev-bind",
            "/dev/kfd",
            "/dev/kfd",
            "--dev-bind",
            "/dev/dri/renderD128",
            "/dev/dri/renderD128"
        ]
    );
    for denied in ["/dev/kfd", "/dev", "/dev/dri/renderD*"] {
        let mut value = raw.clone();
        let path = if denied.contains('*') {
            serde_json::json!({"type": "glob_pattern", "pattern": denied})
        } else {
            serde_json::json!({"type": "path", "path": denied})
        };
        value["entries"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"path": path, "access": "deny"}));
        let profile: codex_protocol::models::PermissionProfile = serde_json::from_value(
            serde_json::json!({"type":"managed", "file_system":value, "network":"restricted"}),
        )
        .unwrap();
        let (policy, _) = profile.to_runtime_permissions();
        assert!(
            policy_device_mount_arguments(selector, &policy, cwd, observed).is_err(),
            "{denied}"
        );
    }
}

#[test]
fn internal_proc_probe_ignores_device_request() {
    const CHILD: &str = "HALOLOOM_TEST_AMD_PREFLIGHT_CHILD";
    if std::env::var_os(CHILD).is_some() {
        use crate::bwrap::BwrapNetworkMode;
        use crate::bwrap::BwrapOptions;
        use codex_protocol::permissions::FileSystemAccessMode;
        use codex_protocol::permissions::FileSystemPath;
        use codex_protocol::permissions::FileSystemSandboxEntry;
        use codex_protocol::permissions::FileSystemSpecialPath;
        let policy = FileSystemSandboxPolicy::restricted(vec![FileSystemSandboxEntry {
            path: FileSystemPath::Special {
                value: FileSystemSpecialPath::Minimal,
            },
            access: FileSystemAccessMode::Read,
            missing_path_behavior: None,
        }]);
        // This is the same minimal policy and default options as the native
        // /proc probe. It must not consume the outer command's GPU request.
        let args = crate::bwrap::create_bwrap_command_args(
            vec!["/usr/bin/true".to_owned()],
            &policy,
            Path::new("/"),
            Path::new("/"),
            BwrapOptions {
                network_mode: BwrapNetworkMode::Isolated,
                ..Default::default()
            },
        )
        .expect("internal probe must not parse an operator device request");
        assert!(!args.args.iter().any(|arg| arg == "--dev-bind"));
        assert!(args.args.iter().any(|arg| arg == "--unshare-net"));
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "amd_gpu::tests::internal_proc_probe_ignores_device_request",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .env(DEVICE_ENV, "not JSON")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn kfd_identity_uses_its_kernel_sysfs_class() {
    let root = tempfile::tempdir().unwrap();
    let class = root.path().join("class/kfd/kfd");
    std::fs::create_dir_all(&class).unwrap();
    std::fs::write(class.join("dev"), "234:0\n").unwrap();
    assert_eq!(
        read_sysfs_identity(Path::new("/dev/kfd"), root.path()).unwrap(),
        ((234, 0), None)
    );
}
