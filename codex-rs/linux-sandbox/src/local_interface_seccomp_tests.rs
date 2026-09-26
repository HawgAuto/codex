//! Subprocess seccomp regressions; never filter the test runner itself.
use super::NetworkSeccompMode;
use super::install_network_seccomp_filter_on_current_thread;
use super::set_no_new_privs;
use std::process::Command;

#[test]
fn default_still_denies_interface_discovery() {
    run_child("disabled");
}
#[test]
fn opt_in_allows_route_discovery_only() {
    run_child("enabled");
}

fn run_child(mode: &str) {
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "landlock::local_interface_seccomp_tests::seccomp_child",
            "--nocapture",
        ])
        .env("HALOLOOM_IFADDRS_TEST_CHILD", mode)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("INTERFACE_SECCOMP_CHILD_PASS"));
}

#[test]
fn seccomp_child() {
    let Ok(mode) = std::env::var("HALOLOOM_IFADDRS_TEST_CHILD") else {
        return;
    };
    let enabled = mode == "enabled";
    set_no_new_privs().unwrap();
    install_network_seccomp_filter_on_current_thread(
        NetworkSeccompMode::ProxyRouted,
        None,
        enabled,
    )
    .unwrap();
    let mut list = std::ptr::null_mut();
    let rc = unsafe { libc::getifaddrs(&mut list) };
    if enabled {
        assert_eq!(rc, 0, "getifaddrs: {}", std::io::Error::last_os_error());
        unsafe { libc::freeifaddrs(list) };
    } else {
        assert_eq!(rc, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EPERM)
        );
    }
    for (domain, protocol) in [
        (libc::AF_NETLINK, libc::NETLINK_USERSOCK),
        (libc::AF_NETLINK, libc::NETLINK_KOBJECT_UEVENT),
        (libc::AF_PACKET, 0),
        (libc::AF_VSOCK, 0),
    ] {
        let fd = unsafe { libc::socket(domain, libc::SOCK_RAW, protocol) };
        assert_eq!(fd, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EPERM)
        );
    }
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    assert!(fd >= 0);
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    request.ifr_name[0] = b'l' as libc::c_char;
    request.ifr_name[1] = b'o' as libc::c_char;
    request.ifr_ifru.ifru_flags = libc::IFF_UP as libc::c_short;
    let rc = unsafe { libc::ioctl(fd, libc::SIOCSIFFLAGS, &request) };
    assert_eq!(rc, -1, "network administration must remain unavailable");
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EPERM)
    );
    unsafe { libc::close(fd) };
    println!("INTERFACE_SECCOMP_CHILD_PASS");
}
