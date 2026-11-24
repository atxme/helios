//! Exercise preflight failures using the actual CLI and no external build tools.

use std::process::{Command, Output};

fn xtask(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(arguments)
        .env("PATH", "")
        .env_remove("HELIOS_PUBLISHER_KEYRING_PATH")
        .output()
        .expect("run xtask preflight")
}

#[test]
fn app_and_bundle_require_a_publisher_keyring_before_building() {
    for command in ["app", "bundle"] {
        let output = xtask(&[
            command,
            "--target",
            "x86_64-unknown-linux-gnu",
            "--skip-frontend",
            "--native",
        ]);
        assert!(
            !output.status.success(),
            "{command} started without a keyring"
        );
        assert!(output.stdout.is_empty());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(
            error.contains(
                "HELIOS_PUBLISHER_KEYRING_PATH must point to the publisher's public keyring"
            ),
            "{command}: {error}"
        );
    }
}

#[cfg(not(windows))]
#[test]
fn msi_command_refuses_to_build_outside_windows_even_with_an_unsigned_request() {
    let output = xtask(&["orion-msi", "--unsigned", "--skip-npm-ci"]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(
        error.contains("an MSI can only be built on Windows"),
        "{error}"
    );
}

#[cfg(target_os = "linux")]
mod container {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;
    use std::process::{Command, Output};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const TARGET: &str = "x86_64-unknown-linux-gnu";

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new(inspect: u8, build: u8, run: u8, produce: bool) -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let root = std::env::temp_dir().join(format!(
                "helios-xtask-container-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).expect("create fixture directory");
            let fixture = Self { root };
            let docker = fixture.root.join("docker");
            fs::write(
                &docker,
                format!(
                    r#"#!/bin/sh
printf '%s\n' "$*" >> "$DOCKER_TRACE"
case "$1" in
    info) exit 0 ;;
    image) exit {inspect} ;;
    build) exit {build} ;;
    run)
        shift
        for arg do
            case "$arg" in
                *:/helios/out) out=${{arg%:/helios/out}} ;;
            esac
        done
        if [ {produce} = true ]; then
            case "$*" in
                *'--output /helios/out/staged') ;;
                *) exit 21 ;;
            esac
            /bin/mkdir "$out/staged" || exit 22
            printf '%s\n' 'simulated gateway executable' > "$out/staged/heliosd"
            /bin/chmod 755 "$out/staged/heliosd" || exit 23
        fi
        exit {run}
        ;;
    *) exit 24 ;;
esac
"#
                ),
            )
            .unwrap();
            fs::set_permissions(docker, fs::Permissions::from_mode(0o755)).unwrap();
            fs::write(fixture.root.join("publisher.json"), "{}").unwrap();
            fs::create_dir(fixture.scratch()).unwrap();
            fixture
        }

        fn scratch(&self) -> PathBuf {
            self.root.join("scratch")
        }

        fn staging(&self) -> PathBuf {
            self.root.join("staged")
        }

        fn xtask(&self, args: &[&str]) -> Output {
            let system_path = std::env::var_os("PATH").unwrap_or_default();
            let mut path = std::env::split_paths(&system_path).collect::<Vec<_>>();
            path.insert(0, self.root.clone());
            Command::new(env!("CARGO_BIN_EXE_xtask"))
                .args(args)
                .current_dir(&self.root)
                .env("PATH", std::env::join_paths(path).unwrap())
                .env("TMPDIR", self.scratch())
                .env("DOCKER_TRACE", self.root.join("docker.log"))
                .env(
                    "HELIOS_PUBLISHER_KEYRING_PATH",
                    self.root.join("publisher.json"),
                )
                .output()
                .expect("run xtask with isolated Docker stub")
        }

        fn bundle(&self) -> Output {
            self.xtask(&[
                "bundle",
                "--target",
                TARGET,
                "--output",
                self.staging().to_str().unwrap(),
            ])
        }

        fn docker_trace(&self) -> Vec<String> {
            fs::read_to_string(self.root.join("docker.log"))
                .unwrap()
                .lines()
                .map(str::to_owned)
                .collect()
        }

        fn assert_scratch_clean(&self) {
            assert!(fs::read_dir(self.scratch()).unwrap().next().is_none());
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn assert_failure(output: Output, expected: &str) {
        assert!(!output.status.success());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(error.contains(expected), "{error}");
    }

    #[test]
    fn container_bundle_builds_missing_image_and_publishes_only_new_output() {
        let fixture = Fixture::new(1, 0, 0, true);
        let staging = fixture.staging();
        fs::create_dir(&staging).unwrap();
        fs::write(staging.join("stale"), "old bundle").unwrap();

        let output = fixture.bundle();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let message = String::from_utf8_lossy(&output.stdout);
        assert!(message.contains("Bundle assembled"));
        assert!(message.contains("Sign on the publisher workstation"));
        assert!(!staging.join("stale").exists());

        let binary = staging.join("heliosd");
        assert_eq!(
            fs::read_to_string(&binary).unwrap(),
            "simulated gateway executable\n"
        );
        assert_ne!(
            fs::metadata(binary).unwrap().permissions().mode() & 0o111,
            0
        );
        let trace = fixture.docker_trace();
        assert_eq!(trace.len(), 4);
        assert_eq!(trace[0], "info");
        assert!(trace[1].starts_with("image inspect helios-build:"));
        assert!(trace[2].starts_with("build -f "));
        assert!(trace[2].contains("tools/build-env/Dockerfile"));
        assert!(trace[3].contains("publisher.json:/helios/keyring.json:ro"));
        assert!(trace[3].contains("SOURCE_DATE_EPOCH="));
        assert!(trace[3].contains("cargo run --locked --package xtask -- bundle --native"));
        fixture.assert_scratch_clean();
    }

    #[test]
    fn container_bundle_preserves_old_staging_when_image_or_command_fails() {
        for (inspect, build, run, count, expected) in [
            (1, 9, 0, 3, "docker build of helios-build:"),
            (0, 0, 9, 3, "the build in the container failed"),
            (0, 0, 0, 3, "was not produced"),
        ] {
            let fixture = Fixture::new(inspect, build, run, false);
            let staging = fixture.staging();
            fs::create_dir(&staging).unwrap();
            fs::write(staging.join("prior-output"), "prior bundle").unwrap();

            assert_failure(fixture.bundle(), expected);
            let trace = fixture.docker_trace();
            assert_eq!(trace.len(), count, "{trace:?}");
            assert_eq!(trace[2].starts_with("build -f "), inspect != 0);
            assert_eq!(
                fs::read_to_string(staging.join("prior-output")).unwrap(),
                "prior bundle"
            );
            fixture.assert_scratch_clean();
        }
    }

    #[test]
    fn container_app_and_bundle_refuse_invalid_options_before_running_docker() {
        let fixture = Fixture::new(0, 0, 0, false);
        for command in ["app", "bundle"] {
            assert_failure(
                fixture.xtask(&[command, "--target", TARGET, "--skip-frontend"]),
                "needs `--native`",
            );
            assert_failure(
                fixture.xtask(&[command, "--target", "aarch64-unknown-linux-gnu"]),
                "the build container only produces x86_64-unknown-linux-gnu",
            );
        }
        assert!(!fixture.root.join("docker.log").exists());
        fixture.assert_scratch_clean();
    }
}
