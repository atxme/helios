//! Pinned build container: the delivery path of the gateway bundle.
//!
//! `cargo xtask bundle` and `cargo xtask app` build inside the image described
//! by `tools/build-env/Dockerfile`, from a copy of the tracked files, with a
//! fixed environment. The host build of the same commands stays behind
//! `--native`.

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
};

use anyhow::{anyhow, bail, Context, Result};

/// Repository of the build image. The tag is `<repository>:<12 hex>`.
pub const IMAGE_REPOSITORY: &str = "helios-build";

/// The only target the container builds.
pub const CONTAINER_TARGET: &str = "x86_64-unknown-linux-gnu";

const DOCKERFILE: &str = "tools/build-env/Dockerfile";
const BUILD_CONTEXT: &str = "tools/build-env";
const CARGO_VOLUME: &str = "helios-build-cargo";
const TARGET_VOLUME: &str = "helios-build-target";
const SOURCE_MOUNT: &str = "/helios/src";
const OUT_MOUNT: &str = "/helios/out";
const KEYRING_MOUNT: &str = "/helios/keyring.json";
const CARGO_HOME_MOUNT: &str = "/helios/cargo";
const TARGET_MOUNT: &str = "/helios/target";
const RUSTFLAGS: &str =
    "--remap-path-prefix=/helios/src=/helios --remap-path-prefix=/helios/cargo=/cargo";

/// Everything `docker run` needs for one build.
pub struct ContainerRun {
    pub image: String,
    pub source: PathBuf,
    pub keyring: PathBuf,
    pub out: PathBuf,
    pub uid: u32,
    pub gid: u32,
    pub source_date_epoch: u64,
    pub jobs: Option<String>,
    pub command: Vec<String>,
}

/// Tag of the image built from the Dockerfile at `dockerfile`.
///
/// Any change to the file, including a version bump, yields a new tag, so an
/// image is never reused for a recipe it was not built from.
pub fn image_tag(dockerfile: &Path) -> Result<String> {
    let digest = helios_update::sha256_file(dockerfile)
        .map_err(|e| anyhow!("fingerprint of {}: {e}", dockerfile.display()))?;
    let prefix: String = digest
        .iter()
        .take(6)
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok(format!("{IMAGE_REPOSITORY}:{prefix}"))
}

/// Fails unless the Docker daemon answers.
pub fn ensure_docker() -> Result<()> {
    let status = Command::new("docker")
        .arg("info")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match status {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(docker_error(Some(status))),
        Err(_) => Err(docker_error(None)),
    }
}

/// The message for an unreachable Docker, whether absent or not answering.
///
/// Both causes are named together: the operator fixes either one, and the
/// `--native` escape hatch is given at the same time.
fn docker_error(status: Option<ExitStatus>) -> anyhow::Error {
    let cause = match status {
        None => "the `docker` command is not available".to_string(),
        Some(status) => format!(
            "`docker info` failed ({status}): the daemon is not running or this user cannot reach it"
        ),
    };
    anyhow!(
        "{cause}: install Docker (rootful, user in the `docker` group) and start it, \
         or rebuild with `--native` to build on this host"
    )
}

/// Builds the image unless it already exists, and returns its tag.
pub fn ensure_image(root: &Path) -> Result<String> {
    let dockerfile = root.join(DOCKERFILE);
    let tag = image_tag(&dockerfile)?;
    let present = Command::new("docker")
        .args(["image", "inspect", &tag])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("running docker image inspect")?
        .success();
    if !present {
        println!("==> Building the build image {tag}");
        let status = Command::new("docker")
            .arg("build")
            .arg("-f")
            .arg(&dockerfile)
            .arg("-t")
            .arg(&tag)
            .arg(root.join(BUILD_CONTEXT))
            .status()
            .context("running docker build")?;
        if !status.success() {
            bail!("docker build of {tag} failed ({status})");
        }
    }
    Ok(tag)
}

/// Copies the tracked files of the repository to `dest`, as they are on disk.
///
/// Nothing else is copied: no ignored file, no untracked file, no `.git`.
/// Executable bits survive the copy, and uncommitted edits to tracked files
/// are copied as they are.
pub fn export_tree(root: &Path, dest: &Path) -> Result<()> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "-z"])
        .output()
        .context("listing the tracked files with git ls-files")?;
    if !output.status.success() {
        bail!(
            "git ls-files failed in {} ({})",
            root.display(),
            output.status
        );
    }
    for raw in output.stdout.split(|byte| *byte == 0) {
        if raw.is_empty() {
            continue;
        }
        let relative =
            std::str::from_utf8(raw).context("git ls-files reported a non-UTF-8 path")?;
        let target = dest.join(relative);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        std::fs::copy(root.join(relative), &target)
            .with_context(|| format!("copying {relative} to {}", target.display()))?;
    }
    Ok(())
}

/// Commit time of the last commit: the reproducible build time.
pub fn source_date_epoch(root: &Path) -> Result<u64> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["log", "-1", "--format=%ct"])
        .output()
        .context("reading the last commit time with git log")?;
    if !output.status.success() {
        bail!("git log failed in {} ({})", root.display(), output.status);
    }
    let text = String::from_utf8_lossy(&output.stdout);
    text.trim()
        .parse()
        .with_context(|| format!("git log did not report a commit time: {:?}", text.trim()))
}

/// The `docker run` arguments of one build, ending with the command.
pub fn run_args(run: &ContainerRun) -> Result<Vec<OsString>> {
    let keyring = std::path::absolute(&run.keyring)
        .with_context(|| format!("resolving the keyring path {}", run.keyring.display()))?;

    let mut args: Vec<OsString> = vec!["run".into(), "--rm".into()];
    option(&mut args, "--user", format!("{}:{}", run.uid, run.gid));
    option(&mut args, "-v", bind_mount(&run.source, SOURCE_MOUNT, "")?);
    option(&mut args, "-v", bind_mount(&keyring, KEYRING_MOUNT, ":ro")?);
    option(&mut args, "-v", bind_mount(&run.out, OUT_MOUNT, "")?);
    option(
        &mut args,
        "-v",
        format!("{CARGO_VOLUME}:{CARGO_HOME_MOUNT}"),
    );
    option(&mut args, "-v", format!("{TARGET_VOLUME}:{TARGET_MOUNT}"));
    option(&mut args, "-w", SOURCE_MOUNT);
    option(&mut args, "-e", format!("RUSTFLAGS={RUSTFLAGS}"));
    option(
        &mut args,
        "-e",
        format!("SOURCE_DATE_EPOCH={}", run.source_date_epoch),
    );
    option(&mut args, "-e", "TZ=UTC");
    option(&mut args, "-e", "LANG=C.UTF-8");
    option(&mut args, "-e", format!("CARGO_HOME={CARGO_HOME_MOUNT}"));
    option(&mut args, "-e", format!("CARGO_TARGET_DIR={TARGET_MOUNT}"));
    option(
        &mut args,
        "-e",
        format!("HELIOS_PUBLISHER_KEYRING_PATH={KEYRING_MOUNT}"),
    );
    if let Some(jobs) = &run.jobs {
        option(&mut args, "-e", format!("CARGO_BUILD_JOBS={jobs}"));
    }
    args.push(run.image.clone().into());
    args.extend(run.command.iter().map(OsString::from));
    Ok(args)
}

fn option(args: &mut Vec<OsString>, flag: &str, value: impl Into<OsString>) {
    args.push(flag.into());
    args.push(value.into());
}

/// A `-v` value binding an absolute host path. `docker -v` splits on `:`, so
/// such a path would be mounted at the wrong place: refused instead.
fn bind_mount(host: &Path, container: &str, suffix: &str) -> Result<OsString> {
    if host.to_string_lossy().contains(':') {
        bail!("{} contains ':', which docker cannot mount", host.display());
    }
    let mut value = host.as_os_str().to_owned();
    value.push(format!(":{container}{suffix}"));
    Ok(value)
}

/// Replaces `to` entirely with `from`: a file or a directory, modes kept.
///
/// An earlier output at `to` is removed first, so no file of a previous build
/// can survive into the new one.
pub fn copy_out(from: &Path, to: &Path) -> Result<()> {
    if !from.exists() {
        bail!("{} was not produced", from.display());
    }
    if let Ok(metadata) = std::fs::symlink_metadata(to) {
        if metadata.is_dir() {
            std::fs::remove_dir_all(to).with_context(|| format!("removing {}", to.display()))?;
        } else {
            std::fs::remove_file(to).with_context(|| format!("removing {}", to.display()))?;
        }
    }
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    if from.is_dir() {
        copy_tree(from, to)
    } else {
        std::fs::copy(from, to)
            .with_context(|| format!("copying {} to {}", from.display(), to.display()))?;
        Ok(())
    }
}

fn copy_tree(from: &Path, to: &Path) -> Result<()> {
    std::fs::create_dir_all(to).with_context(|| format!("creating {}", to.display()))?;
    let permissions = std::fs::metadata(from)
        .with_context(|| format!("reading {}", from.display()))?
        .permissions();
    std::fs::set_permissions(to, permissions)
        .with_context(|| format!("setting the mode of {}", to.display()))?;
    for entry in std::fs::read_dir(from).with_context(|| format!("reading {}", from.display()))? {
        let entry = entry.with_context(|| format!("reading {}", from.display()))?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), &target)
                .with_context(|| format!("copying {}", entry.path().display()))?;
        }
    }
    Ok(())
}

/// Removes the scratch directory that holds an output returned by
/// [`build_in_container`], once that output has been copied out.
pub fn discard(out: &Path) -> Result<()> {
    let scratch = out.parent().unwrap_or(out);
    std::fs::remove_dir_all(scratch).with_context(|| format!("removing {}", scratch.display()))
}

/// Runs `command` in the build image and returns the host directory mounted on
/// `/helios/out`, which the caller copies out and then [`discard`]s.
///
/// `keyring` is the publisher's public keyring; it reaches the container
/// read-only and no private material does.
pub fn build_in_container(root: &Path, keyring: &Path, command: Vec<String>) -> Result<PathBuf> {
    ensure_docker()?;
    let image = ensure_image(root)?;
    let scratch = scratch_directory()?;
    let prepared = prepare(root, &image, &scratch, keyring, command);
    if prepared.is_err() {
        let _ = std::fs::remove_dir_all(&scratch);
    }
    prepared
}

fn prepare(
    root: &Path,
    image: &str,
    scratch: &Path,
    keyring: &Path,
    command: Vec<String>,
) -> Result<PathBuf> {
    let source = scratch.join("src");
    let out = scratch.join("out");
    std::fs::create_dir_all(&out).with_context(|| format!("creating {}", out.display()))?;
    export_tree(root, &source)?;

    let run = ContainerRun {
        image: image.to_string(),
        source: source.clone(),
        keyring: keyring.to_path_buf(),
        out: out.clone(),
        uid: caller_id("-u")?,
        gid: caller_id("-g")?,
        source_date_epoch: source_date_epoch(root)?,
        jobs: std::env::var("CARGO_BUILD_JOBS")
            .ok()
            .filter(|jobs| !jobs.is_empty()),
        command,
    };
    let args = run_args(&run)?;
    let status = Command::new("docker")
        .args(&args)
        .status()
        .context("running docker run")?;
    if !status.success() {
        bail!("the build in the container failed ({status})");
    }
    std::fs::remove_dir_all(&source).with_context(|| format!("removing {}", source.display()))?;
    Ok(out)
}

fn caller_id(flag: &str) -> Result<u32> {
    let output = Command::new("id")
        .arg(flag)
        .output()
        .with_context(|| format!("running id {flag}"))?;
    if !output.status.success() {
        bail!("id {flag} failed ({})", output.status);
    }
    let text = String::from_utf8_lossy(&output.stdout);
    text.trim()
        .parse()
        .with_context(|| format!("id {flag} did not report a number: {:?}", text.trim()))
}

fn scratch_directory() -> Result<PathBuf> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    let path = std::env::temp_dir().join(format!("helios-build-{}-{nanos}", std::process::id()));
    std::fs::create_dir(&path).with_context(|| format!("creating {}", path.display()))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch directory removed when dropped.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(label: &str) -> Self {
            use std::sync::atomic::{AtomicUsize, Ordering};

            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "helios-container-{label}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("create scratch directory");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn sample_run(keyring: PathBuf) -> ContainerRun {
        ContainerRun {
            image: "helios-build:0123456789ab".into(),
            source: PathBuf::from("/work/src"),
            keyring,
            out: PathBuf::from("/work/out"),
            uid: 1000,
            gid: 1000,
            source_date_epoch: 1_700_000_000,
            jobs: None,
            command: vec!["cargo".into(), "--version".into()],
        }
    }

    fn strings(args: &[OsString]) -> Vec<String> {
        args.iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    fn git(root: &Path, args: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .env("GIT_AUTHOR_NAME", "test")
            .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
            .env("GIT_COMMITTER_NAME", "test")
            .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
            .status()
            .expect("run git");
        assert!(status.success(), "git {args:?} failed");
    }

    fn write(path: &Path, content: &str) {
        std::fs::create_dir_all(path.parent().expect("parent")).expect("create parent");
        std::fs::write(path, content).expect("write file");
    }

    fn files_under(root: &Path) -> Vec<String> {
        fn walk(root: &Path, current: &Path, found: &mut Vec<String>) {
            for entry in std::fs::read_dir(current).expect("read directory") {
                let path = entry.expect("entry").path();
                if path.is_dir() {
                    walk(root, &path, found);
                } else {
                    found.push(
                        path.strip_prefix(root)
                            .expect("inside root")
                            .to_string_lossy()
                            .replace('\\', "/"),
                    );
                }
            }
        }
        let mut found = Vec::new();
        walk(root, root, &mut found);
        found.sort();
        found
    }

    #[test]
    fn image_tag_changes_with_the_dockerfile() {
        let scratch = Scratch::new("tag");
        let first = scratch.path().join("first");
        let second = scratch.path().join("second");
        write(&first, "FROM debian\n");
        write(&second, "FROM debian\nRUN true\n");

        let first_tag = image_tag(&first).expect("first tag");
        let second_tag = image_tag(&second).expect("second tag");

        assert_ne!(first_tag, second_tag);
        for tag in [&first_tag, &second_tag] {
            let (repository, digest) = tag.split_once(':').expect("repository:digest");
            assert_eq!(repository, IMAGE_REPOSITORY);
            assert_eq!(digest.len(), 12);
            assert!(digest
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        }
    }

    #[test]
    fn run_args_carry_the_fixed_environment() {
        let scratch = Scratch::new("env");
        let keyring = scratch.path().join("keyring.json");
        write(&keyring, "{}");
        let args = strings(&run_args(&sample_run(keyring.clone())).expect("run args"));

        let has = |expected: &str| args.iter().any(|arg| arg == expected);
        let rustflags = args
            .iter()
            .find(|arg| arg.starts_with("RUSTFLAGS="))
            .expect("RUSTFLAGS argument");
        assert!(rustflags.contains("--remap-path-prefix=/helios/src=/helios"));
        assert!(rustflags.contains("--remap-path-prefix=/helios/cargo=/cargo"));
        assert!(has("SOURCE_DATE_EPOCH=1700000000"));
        assert!(has("TZ=UTC"));
        assert!(has("LANG=C.UTF-8"));
        assert!(has("CARGO_HOME=/helios/cargo"));
        assert!(has("CARGO_TARGET_DIR=/helios/target"));
        assert!(has("HELIOS_PUBLISHER_KEYRING_PATH=/helios/keyring.json"));
        assert!(args.windows(2).any(|pair| pair == ["--user", "1000:1000"]));
        assert!(has("helios-build-cargo:/helios/cargo"));
        assert!(has("helios-build-target:/helios/target"));
        assert!(has(&format!(
            "{}:/helios/keyring.json:ro",
            keyring.display()
        )));
        assert!(args.ends_with(&[
            "helios-build:0123456789ab".to_string(),
            "cargo".to_string(),
            "--version".to_string(),
        ]));
    }

    #[test]
    fn run_args_mount_the_keyring_by_absolute_path() {
        let relative = PathBuf::from("rel dir/keyring.json");
        let args = strings(&run_args(&sample_run(relative)).expect("run args"));

        let mount = args
            .iter()
            .find(|arg| arg.ends_with(":/helios/keyring.json:ro"))
            .expect("keyring mount argument");
        let host = mount
            .strip_suffix(":/helios/keyring.json:ro")
            .expect("suffix");
        assert!(Path::new(host).is_absolute(), "{host} is not absolute");
        assert!(host.ends_with("rel dir/keyring.json"));
    }

    #[test]
    fn run_args_forward_cargo_build_jobs_only_when_set() {
        let scratch = Scratch::new("jobs");
        let keyring = scratch.path().join("keyring.json");
        write(&keyring, "{}");

        let unset = strings(&run_args(&sample_run(keyring.clone())).expect("run args"));
        assert!(!unset.iter().any(|arg| arg.starts_with("CARGO_BUILD_JOBS=")));

        let mut run = sample_run(keyring);
        run.jobs = Some("2".into());
        let set = strings(&run_args(&run).expect("run args"));
        assert!(set.iter().any(|arg| arg == "CARGO_BUILD_JOBS=2"));
    }

    #[test]
    fn export_tree_takes_only_tracked_files() {
        let scratch = Scratch::new("export");
        let repo = scratch.path().join("repo");
        std::fs::create_dir_all(&repo).expect("create repo");
        git(&repo, &["init", "--quiet"]);
        write(&repo.join("src/lib.rs"), "pub fn old() {}\n");
        write(&repo.join("bin/run"), "#!/bin/sh\n");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(repo.join("bin/run"), std::fs::Permissions::from_mode(0o755))
                .expect("make script executable");
        }
        git(&repo, &["add", "src/lib.rs", "bin/run"]);
        write(&repo.join("scratch.txt"), "untracked\n");
        write(&repo.join("node_modules/x"), "ignored\n");
        write(&repo.join("web/dist/y"), "ignored\n");
        write(&repo.join("src/lib.rs"), "pub fn edited() {}\n");

        let dest = scratch.path().join("dest");
        export_tree(&repo, &dest).expect("export");

        assert_eq!(
            files_under(&dest),
            vec!["bin/run".to_string(), "src/lib.rs".to_string()]
        );
        assert_eq!(
            std::fs::read_to_string(dest.join("src/lib.rs")).expect("read copy"),
            "pub fn edited() {}\n"
        );
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dest.join("bin/run"))
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o755);
        }
    }

    #[test]
    fn source_date_epoch_is_the_last_commit_time() {
        let scratch = Scratch::new("epoch");
        let repo = scratch.path().join("repo");
        std::fs::create_dir_all(&repo).expect("create repo");
        git(&repo, &["init", "--quiet"]);
        write(&repo.join("file"), "content\n");
        git(&repo, &["add", "file"]);
        let status = Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(["commit", "--quiet", "-m", "fixture"])
            .env("GIT_AUTHOR_NAME", "test")
            .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
            .env("GIT_COMMITTER_NAME", "test")
            .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
            .env("GIT_COMMITTER_DATE", "@1700000000 +0000")
            .env("GIT_AUTHOR_DATE", "@1700000000 +0000")
            .status()
            .expect("run git commit");
        assert!(status.success());

        assert_eq!(source_date_epoch(&repo).expect("epoch"), 1_700_000_000);
    }

    #[test]
    fn copy_out_replaces_an_existing_destination() {
        let scratch = Scratch::new("copy-out");
        let from = scratch.path().join("from");
        let to = scratch.path().join("to");
        write(&from.join("heliosd"), "new\n");
        write(&to.join("stale"), "old\n");

        copy_out(&from, &to).expect("copy out");

        assert!(
            !to.join("stale").exists(),
            "a file of the previous output survived"
        );
        assert_eq!(files_under(&to), vec!["heliosd".to_string()]);
    }

    #[test]
    fn copy_out_keeps_the_mode_of_a_single_file() {
        use std::os::unix::fs::PermissionsExt;

        let scratch = Scratch::new("copy-file");
        let from = scratch.path().join("heliosd");
        let to = scratch.path().join("release").join("heliosd");
        write(&from, "binary\n");
        std::fs::set_permissions(&from, std::fs::Permissions::from_mode(0o755))
            .expect("make binary executable");
        write(&to, "previous\n");

        copy_out(&from, &to).expect("copy out");

        assert_eq!(std::fs::read_to_string(&to).expect("read"), "binary\n");
        let mode = std::fs::metadata(&to)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o755);
    }

    #[test]
    fn docker_unavailable_is_reported_before_building() {
        use std::os::unix::process::ExitStatusExt;

        for error in [
            docker_error(None),
            docker_error(Some(ExitStatus::from_raw(1 << 8))),
        ] {
            let message = error.to_string();
            assert!(message.contains("--native"), "{message}");
            assert!(message.contains("docker"), "{message}");
            assert!(message.contains("user in the `docker` group"), "{message}");
        }
    }
}
