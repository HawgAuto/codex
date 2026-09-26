//! Default-off interface discovery inside a proxy-routed command namespace.
//! Only NETLINK_ROUTE is requested; capability-free execution keeps mutation
//! unavailable. This does not grant network egress or change filesystem policy.
use std::io;

const ENV: &str = "HALOLOOM_CODEX_LOCAL_INTERFACE_DISCOVERY";

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

fn validate(
    raw: Option<&str>,
    proxy_routed: bool,
    local_ipc: bool,
    status: &str,
) -> io::Result<bool> {
    // Internal namespace probes must not consume command-only opt-ins.
    if !proxy_routed || matches!(raw, None | Some("0")) {
        return Ok(false);
    }
    if raw != Some("1") {
        return Err(invalid(
            "HALOLOOM_CODEX_LOCAL_INTERFACE_DISCOVERY must be 0 or 1",
        ));
    }
    if !local_ipc {
        return Err(invalid(
            "interface discovery requires the explicit local IPC policy",
        ));
    }
    for field in ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"] {
        let value = status
            .lines()
            .find_map(|line| line.strip_prefix(field))
            .ok_or_else(|| invalid("missing command capability status"))?;
        let value = u64::from_str_radix(value.trim(), 16)
            .map_err(|_| invalid("malformed command capability status"))?;
        if value != 0 {
            return Err(invalid(
                "interface discovery requires a capability-free command",
            ));
        }
    }
    Ok(true)
}

pub(crate) fn requested(proxy_routed: bool, local_ipc: bool) -> io::Result<bool> {
    if !proxy_routed {
        return Ok(false);
    }
    let raw = std::env::var(ENV).map(Some).or_else(|error| match error {
        std::env::VarError::NotPresent => Ok(None),
        std::env::VarError::NotUnicode(_) => {
            Err(invalid("interface discovery opt-in is not UTF-8"))
        }
    })?;
    let status = if raw.as_deref() == Some("1") {
        std::fs::read_to_string("/proc/self/status")?
    } else {
        String::new()
    };
    validate(raw.as_deref(), proxy_routed, local_ipc, &status)
}

#[cfg(test)]
mod tests {
    use super::validate;
    const EMPTY_CAPS: &str =
        "CapInh:\t00000000\nCapPrm:\t00000000\nCapEff:\t00000000\nCapAmb:\t00000000\n";
    #[test]
    fn default_is_disabled() {
        assert!(!validate(None, true, true, "").unwrap());
    }
    #[test]
    fn explicit_zero_is_disabled() {
        assert!(!validate(Some("0"), true, true, "").unwrap());
    }
    #[test]
    fn namespace_probe_ignores_ambient_opt_in() {
        assert!(!validate(Some("malformed"), false, true, "").unwrap());
    }
    #[test]
    fn rejects_malformed_opt_in() {
        assert!(validate(Some("typo"), true, true, EMPTY_CAPS).is_err());
    }
    #[test]
    fn rejects_missing_local_ipc() {
        assert!(validate(Some("1"), true, false, EMPTY_CAPS).is_err());
    }
    #[test]
    fn accepts_explicit_capability_free_local_command() {
        assert!(validate(Some("1"), true, true, EMPTY_CAPS).unwrap());
    }
    #[test]
    fn rejects_missing_capability_record() {
        assert!(validate(Some("1"), true, true, "").is_err());
    }
    #[test]
    fn rejects_each_nonzero_capability_set() {
        for field in ["CapInh", "CapPrm", "CapEff", "CapAmb"] {
            let status = EMPTY_CAPS.replace(
                &format!("{field}:\t00000000"),
                &format!("{field}:\t00001000"),
            );
            assert!(validate(Some("1"), true, true, &status).is_err());
        }
    }
}
