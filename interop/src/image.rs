//! The guest image: an Alpine kernel, booted directly, with an initramfs
//! holding busybox, the few modules the tests need, and the agent as the
//! program `/init` hands over to.
//!
//! Downloads are cached under `interop/.cache`, keyed by Alpine repository
//! and package version, so a second run fetches only the package index
//! (and that once a day). The host needs `curl`, `tar` and `gzip`, which
//! macOS and every Linux CI image have; the cpio archive is written here.

use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

/// The Alpine branch busybox, and the default kernel, come from. A branch,
/// not a point release: Alpine keeps only the newest build of each package
/// in a branch, so the version within it is read from its index.
pub const ALPINE_BRANCH: &str = "v3.24";
const MIRROR: &str = "https://dl-cdn.alpinelinux.org/alpine";

/// Modules the guest needs where the kernel does not have them built in.
/// What they depend on is read from the kernel's `modules.dep`.
const MODULES: &[&str] = &[
    "virtio_pci",
    "virtio_console",
    "virtio_net",
    "tcp_bbr",
    "sch_fq",
];

/// The guest's address on the test link, and the harness's (vclient's).
pub const GUEST_IP: &str = "10.0.2.2";
pub const HOST_IP: &str = "10.0.2.1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    Aarch64,
    X86_64,
}

impl Arch {
    pub fn host() -> Arch {
        if cfg!(target_arch = "aarch64") {
            Arch::Aarch64
        } else {
            Arch::X86_64
        }
    }

    pub fn parse(s: &str) -> Option<Arch> {
        match s {
            "aarch64" | "arm64" => Some(Arch::Aarch64),
            "x86_64" | "amd64" => Some(Arch::X86_64),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Arch::Aarch64 => "aarch64",
            Arch::X86_64 => "x86_64",
        }
    }

    pub fn rust_target(self) -> &'static str {
        match self {
            Arch::Aarch64 => "aarch64-unknown-linux-musl",
            Arch::X86_64 => "x86_64-unknown-linux-musl",
        }
    }
}

/// Which kernel the guest runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kernel {
    /// The branch's `linux-virt`: the LTS kernel (6.18 in v3.24), built for
    /// VMs, 40 MB. What CI runs.
    Lts,
    /// `linux-stable` from edge/community: the newest stable kernel (130
    /// MB), for what the LTS one lacks. AccECN, for one, can be switched on
    /// only from Linux 7.0: 6.18 has the code, but caps `tcp_ecn` at 2.
    Stable,
}

impl Kernel {
    pub fn parse(s: &str) -> Option<Kernel> {
        match s {
            "lts" | "virt" => Some(Kernel::Lts),
            "stable" => Some(Kernel::Stable),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Kernel::Lts => "lts",
            Kernel::Stable => "stable",
        }
    }

    fn repo(self) -> String {
        match self {
            Kernel::Lts => format!("{ALPINE_BRANCH}/main"),
            Kernel::Stable => "edge/community".into(),
        }
    }

    fn package(self) -> &'static str {
        match self {
            Kernel::Lts => "linux-virt",
            Kernel::Stable => "linux-stable",
        }
    }

    fn image(self) -> &'static str {
        match self {
            Kernel::Lts => "vmlinuz-virt",
            Kernel::Stable => "vmlinuz-stable",
        }
    }
}

#[derive(Debug)]
pub struct Image {
    pub kernel: PathBuf,
    pub initrd: PathBuf,
    /// The kernel package and version, e.g. `linux-virt-6.18.54-r0`.
    pub kernel_pkg: String,
}

pub fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run(cmd: &mut Command) -> io::Result<()> {
    let st = cmd.status()?;
    if st.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("{cmd:?} failed: {st}")))
    }
}

/// Download `url` to `dest` unless it is already there.
fn fetch(url: &str, dest: &Path) -> io::Result<()> {
    if dest.exists() {
        return Ok(());
    }
    eprintln!("fetching {url}");
    let tmp = dest.with_extension("part");
    run(Command::new("curl")
        .args(["-fsSL", "--retry", "3", "-o"])
        .arg(&tmp)
        .arg(url))?;
    fs::rename(&tmp, dest)
}

/// An Alpine repository for one architecture, cached.
struct Repo {
    url: String,
    cache: PathBuf,
    index: String,
}

impl Repo {
    /// Open `repo` (e.g. `v3.24/main`), fetching its index again once a
    /// day: a new build within a branch replaces the old one on the
    /// mirror, which then 404s.
    fn open(repo: &str, arch: Arch) -> io::Result<Repo> {
        let url = format!("{MIRROR}/{repo}/{}", arch.name());
        let cache = root()
            .join(".cache")
            .join("alpine")
            .join(repo.replace('/', "-"))
            .join(arch.name());
        fs::create_dir_all(&cache)?;
        let path = cache.join("APKINDEX.tar.gz");
        let stale = fs::metadata(&path)
            .and_then(|m| m.modified())
            .map(|t| {
                SystemTime::now().duration_since(t).unwrap_or_default() > Duration::from_secs(86400)
            })
            .unwrap_or(true);
        if stale {
            let fresh = cache.join("APKINDEX.new");
            let _ = fs::remove_file(&fresh);
            match fetch(&format!("{url}/APKINDEX.tar.gz"), &fresh) {
                Ok(()) => fs::rename(&fresh, &path)?,
                // Offline: the cached index, and packages, will do.
                Err(e) => eprintln!("warning: could not refresh the {repo} index: {e}"),
            }
        }
        let out = Command::new("tar")
            .arg("-xzOf")
            .arg(&path)
            .arg("APKINDEX")
            .output()?;
        if !out.status.success() {
            return Err(io::Error::other(format!("{repo}: unreadable APKINDEX")));
        }
        Ok(Repo {
            url,
            cache,
            index: String::from_utf8_lossy(&out.stdout).into_owned(),
        })
    }

    /// Fetch `pkg` and unpack it into its own directory under the cache.
    /// Returns the directory and `pkg-version`.
    fn package(&self, pkg: &str) -> io::Result<(PathBuf, String)> {
        let ver = version(&self.index, pkg)
            .ok_or_else(|| io::Error::other(format!("{pkg} is not in {}", self.url)))?;
        let name = format!("{pkg}-{ver}");
        let apk = self.cache.join(format!("{name}.apk"));
        fetch(&format!("{}/{name}.apk", self.url), &apk)?;
        let dir = self.cache.join(&name);
        let done = dir.join(".unpacked");
        if !done.exists() {
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir)?;
            // An .apk is gzip'd tar segments, concatenated; tar reads through
            // them, and complains about the signature's pax headers, which is
            // not a failure: what is missing shows when it is looked for.
            let _ = Command::new("tar")
                .arg("-xzf")
                .arg(&apk)
                .arg("-C")
                .arg(&dir)
                .stderr(std::process::Stdio::null())
                .status()?;
            fs::write(&done, b"")?;
        }
        Ok((dir, name))
    }
}

/// A package's version in an index.
fn version(index: &str, pkg: &str) -> Option<String> {
    index.split("\n\n").find_map(|rec| {
        let mut name = None;
        let mut ver = None;
        for l in rec.lines() {
            if let Some(v) = l.strip_prefix("P:") {
                name = Some(v);
            } else if let Some(v) = l.strip_prefix("V:") {
                ver = Some(v);
            }
        }
        (name == Some(pkg))
            .then(|| ver.map(str::to_string))
            .flatten()
    })
}

/// A module's name as the kernel knows it: `-` and `_` are the same.
fn modname(path: &str) -> String {
    let base = path.rsplit('/').next().unwrap_or(path);
    base.split(".ko").next().unwrap_or(base).replace('-', "_")
}

/// The modules to load for `want`, dependencies first, as paths relative
/// to the modules directory; modules built into the kernel are left out.
fn resolve(dep: &str, builtin: &str, want: &[&str]) -> Result<Vec<String>, String> {
    let deps: HashMap<String, (String, Vec<String>)> = dep
        .lines()
        .filter_map(|l| l.split_once(':'))
        .map(|(m, d)| {
            (
                modname(m),
                (m.to_string(), d.split_whitespace().map(modname).collect()),
            )
        })
        .collect();
    let builtin: Vec<String> = builtin.lines().map(modname).collect();
    fn visit(
        m: &str,
        deps: &HashMap<String, (String, Vec<String>)>,
        out: &mut Vec<String>,
        seen: &mut Vec<String>,
    ) {
        if seen.iter().any(|s| s == m) {
            return;
        }
        seen.push(m.to_string());
        if let Some((path, ds)) = deps.get(m) {
            for d in ds {
                visit(d, deps, out, seen);
            }
            out.push(path.clone());
        }
    }
    let (mut out, mut seen) = (Vec::new(), Vec::new());
    for w in want {
        if builtin.iter().any(|b| b == w) {
            continue;
        }
        if !deps.contains_key(*w) {
            return Err(format!("module {w} is neither built in nor in modules.dep"));
        }
        visit(w, &deps, &mut out, &mut seen);
    }
    Ok(out)
}

/// Build the agent for the guest.
fn build_agent(arch: Arch) -> io::Result<PathBuf> {
    let root = root();
    let target_dir = root.join("target").join("agent");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    // The target's flags are in .cargo/config.toml, and RUSTFLAGS from
    // the environment (CI sets it) would replace them, not add to them.
    run(Command::new(cargo)
        .current_dir(&root)
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .args([
            "build",
            "--release",
            "-q",
            "-p",
            "pktkit-interop-agent",
            "--target",
        ])
        .arg(arch.rust_target())
        .arg("--target-dir")
        .arg(&target_dir))?;
    Ok(target_dir
        .join(arch.rust_target())
        .join("release")
        .join("pktkit-interop-agent"))
}

/// A module file's contents, decompressed.
fn module(path: &Path) -> io::Result<Vec<u8>> {
    if path.extension().is_some_and(|e| e == "ko") {
        return fs::read(path);
    }
    let out = Command::new("gzip").arg("-dc").arg(path).output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!("gzip -dc {}", path.display())));
    }
    Ok(out.stdout)
}

/// A newc ("070701") cpio archive, the format the kernel unpacks an
/// initramfs from.
struct Cpio {
    out: Vec<u8>,
    ino: u32,
}

impl Cpio {
    fn new() -> Cpio {
        Cpio {
            out: Vec::new(),
            ino: 1,
        }
    }

    fn pad(&mut self) {
        while !self.out.len().is_multiple_of(4) {
            self.out.push(0);
        }
    }

    fn entry(&mut self, name: &str, mode: u32, rdev: (u32, u32), data: &[u8]) {
        let fields = [
            self.ino,
            mode,
            0,
            0,
            1,
            0,
            data.len() as u32,
            0,
            0,
            rdev.0,
            rdev.1,
            name.len() as u32 + 1,
            0,
        ];
        self.ino += 1;
        self.out.extend_from_slice(b"070701");
        for f in fields {
            let _ = write!(self.out, "{f:08x}");
        }
        self.out.extend_from_slice(name.as_bytes());
        self.out.push(0);
        self.pad();
        self.out.extend_from_slice(data);
        self.pad();
    }

    fn dir(&mut self, name: &str) {
        self.entry(name, 0o040755, (0, 0), &[]);
    }

    fn file(&mut self, name: &str, mode: u32, data: &[u8]) {
        self.entry(name, 0o100000 | mode, (0, 0), data);
    }

    fn finish(mut self) -> Vec<u8> {
        self.entry("TRAILER!!!", 0, (0, 0), &[]);
        // The kernel reads the archive in 512-byte blocks.
        while !self.out.len().is_multiple_of(512) {
            self.out.push(0);
        }
        self.out
    }
}

fn init_script(mods: &[String]) -> String {
    format!(
        r#"#!/bin/busybox sh
/bin/busybox --install -s /bin
export PATH=/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
for m in {mods}; do insmod /lib/modules/$m.ko || echo "init: insmod $m failed"; done
# A module's devices appear once its probe has run.
for i in 1 2 3 4 5 6 7 8 9 10; do [ -e /dev/hvc0 ] && [ -e /sys/class/net/eth0 ] && break; sleep 0.2; done
ifconfig lo 127.0.0.1 up
ifconfig eth0 {GUEST_IP} netmask 255.255.255.0 up
# Everything off the link goes through the harness: slirp's NAT tests.
route add default gw {HOST_IP}
echo "init: starting the agent"
/bin/agent /dev/hvc0
echo "init: the agent exited"
poweroff -f
"#,
        mods = mods.join(" ")
    )
}

/// Build (or reuse) the image for `arch`.
pub fn build(arch: Arch, kernel: Kernel) -> io::Result<Image> {
    let main = Repo::open(&format!("{ALPINE_BRANCH}/main"), arch)?;
    let (bdir, _) = main.package("busybox-static")?;
    let krepo = match kernel {
        Kernel::Lts => main,
        Kernel::Stable => Repo::open(&kernel.repo(), arch)?,
    };
    let (kdir, kpkg) = krepo.package(kernel.package())?;

    let vmlinuz = kdir.join("boot").join(kernel.image());
    if !vmlinuz.exists() {
        return Err(io::Error::other(format!("{} missing", vmlinuz.display())));
    }
    let moddir = fs::read_dir(kdir.join("lib").join("modules"))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| p.is_dir())
        .ok_or_else(|| io::Error::other(format!("no modules directory in {kpkg}")))?;
    let mods = resolve(
        &fs::read_to_string(moddir.join("modules.dep"))?,
        &fs::read_to_string(moddir.join("modules.builtin")).unwrap_or_default(),
        MODULES,
    )
    .map_err(io::Error::other)?;

    let agent = build_agent(arch)?;

    let mut cpio = Cpio::new();
    for d in ["bin", "dev", "proc", "sys", "tmp", "lib", "lib/modules"] {
        cpio.dir(d);
    }
    // Without a console node the kernel starts init with no stdio at all.
    cpio.entry("dev/console", 0o020600, (5, 1), &[]);
    let names: Vec<String> = mods.iter().map(|m| modname(m)).collect();
    cpio.file("init", 0o755, init_script(&names).as_bytes());
    cpio.file(
        "bin/busybox",
        0o755,
        &fs::read(bdir.join("bin").join("busybox.static"))?,
    );
    cpio.file("bin/agent", 0o755, &fs::read(&agent)?);
    for (m, name) in mods.iter().zip(&names) {
        cpio.file(
            &format!("lib/modules/{name}.ko"),
            0o644,
            &module(&moddir.join(m))?,
        );
    }

    let out = root().join("target").join("image").join(arch.name());
    fs::create_dir_all(&out)?;
    let initrd = out.join(format!("initramfs-{}.cpio", kernel.name()));
    fs::write(&initrd, cpio.finish())?;
    Ok(Image {
        kernel: vmlinuz,
        initrd,
        kernel_pkg: kpkg,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpio_entries_are_aligned() {
        let mut c = Cpio::new();
        c.file("a", 0o644, b"xyz");
        c.dir("bb");
        let out = c.finish();
        assert_eq!(&out[..6], b"070701");
        // Header (110) + "a\0" padded to 112, then 3 data bytes padded to 4.
        assert_eq!(&out[116..122], b"070701");
        assert_eq!(out.len() % 512, 0);
    }

    #[test]
    fn index_lookup() {
        let idx = "C:x\nP:foo\nV:1.0-r1\n\nP:linux-virt\nV:6.18.54-r0\nA:x86_64\n";
        assert_eq!(version(idx, "linux-virt").as_deref(), Some("6.18.54-r0"));
        assert_eq!(version(idx, "bar"), None);
    }

    #[test]
    fn modules_come_after_their_dependencies() {
        let dep = "kernel/drivers/net/virtio_net.ko.gz: kernel/drivers/net/net_failover.ko.gz kernel/net/core/failover.ko.gz\n\
                   kernel/drivers/net/net_failover.ko.gz: kernel/net/core/failover.ko.gz\n\
                   kernel/net/core/failover.ko.gz:\n\
                   kernel/net/ipv4/tcp_bbr.ko.gz:\n";
        let builtin = "kernel/drivers/virtio/virtio_pci.ko\n";
        let got = resolve(dep, builtin, &["virtio_pci", "virtio_net", "tcp_bbr"]).unwrap();
        let names: Vec<String> = got.iter().map(|m| modname(m)).collect();
        assert_eq!(names, ["failover", "net_failover", "virtio_net", "tcp_bbr"]);
        assert!(resolve(dep, builtin, &["nope"]).is_err());
    }
}
