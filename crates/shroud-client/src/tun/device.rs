use anyhow::Result;
use shroud_core::config::TunInboundConfig;
use std::fs::File;

#[derive(Debug)]
pub struct TunDevice {
    file: File,
    name: String,
}

impl TunDevice {
    pub fn file(&self) -> &File {
        &self.file
    }

    pub fn into_file(self) -> File {
        self.file
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

pub fn open(config: &TunInboundConfig) -> Result<TunDevice> {
    platform::open(config)
}

#[cfg(target_os = "linux")]
mod platform {
    use super::TunDevice;
    use anyhow::{Context, Result, bail, ensure};
    use shroud_core::config::TunInboundConfig;
    use std::ffi::CStr;
    use std::fs::OpenOptions;
    use std::os::fd::AsRawFd;
    use std::os::raw::{c_char, c_int, c_short, c_ulong};

    const DEV_NET_TUN: &str = "/dev/net/tun";
    const IFNAMSIZ: usize = 16;
    const IFF_TUN: c_short = 0x0001;
    // Disable the extra 4-byte packet information header.
    // With IFF_NO_PI, the TUN fd reads/writes pure IP packets.
    const IFF_NO_PI: c_short = 0x1000;
    const TUNSETIFF: c_ulong = 0x400454ca;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct IfReq {
        name: [c_char; IFNAMSIZ],
        flags: c_short,
        padding: [u8; 22],
    }

    unsafe extern "C" {
        fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
    }

    pub fn open(config: &TunInboundConfig) -> Result<TunDevice> {
        let mut ifreq = build_ifreq(&config.name)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(DEV_NET_TUN)
            .with_context(|| {
                format!("failed to open {DEV_NET_TUN}; TUN requires Linux and CAP_NET_ADMIN/root")
            })?;

        let rc = unsafe { ioctl(file.as_raw_fd(), TUNSETIFF, &mut ifreq) };
        if rc < 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!(
                    "failed to create TUN interface {}; CAP_NET_ADMIN/root is required",
                    config.name
                )
            });
        }

        Ok(TunDevice {
            file,
            name: ifreq_name(&ifreq)?,
        })
    }

    fn build_ifreq(name: &str) -> Result<IfReq> {
        ensure!(!name.is_empty(), "TUN interface name cannot be empty");
        ensure!(
            !name.as_bytes().contains(&0),
            "TUN interface name cannot contain NUL bytes"
        );
        ensure!(
            name.len() < IFNAMSIZ,
            "TUN interface name is too long: {name}; maximum is {} bytes",
            IFNAMSIZ - 1
        );

        let mut ifreq = IfReq {
            name: [0; IFNAMSIZ],
            flags: IFF_TUN | IFF_NO_PI,
            padding: [0; 22],
        };

        for (dst, src) in ifreq.name.iter_mut().zip(name.bytes()) {
            *dst = src as c_char;
        }

        Ok(ifreq)
    }

    fn ifreq_name(ifreq: &IfReq) -> Result<String> {
        let raw = ifreq.name.as_ptr();
        let name = unsafe { CStr::from_ptr(raw) }
            .to_str()
            .context("kernel returned non-utf8 TUN interface name")?;
        if name.is_empty() {
            bail!("kernel returned empty TUN interface name");
        }
        Ok(name.to_string())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn build_ifreq_sets_name_and_flags() {
            let ifreq = build_ifreq("tun-test0").expect("ifreq");

            assert_eq!(ifreq_name(&ifreq).expect("name"), "tun-test0");
            assert_eq!(ifreq.flags, IFF_TUN | IFF_NO_PI);
        }

        #[test]
        fn build_ifreq_rejects_invalid_names() {
            assert!(build_ifreq("").is_err());
            assert!(build_ifreq("tun\0bad").is_err());
            assert!(build_ifreq("1234567890123456").is_err());
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use super::TunDevice;
    use anyhow::{Result, bail};
    use shroud_core::config::TunInboundConfig;

    pub fn open(_config: &TunInboundConfig) -> Result<TunDevice> {
        bail!("TUN device setup is currently implemented only on Linux")
    }
}
