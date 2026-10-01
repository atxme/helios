"""Failure-path tests; never mount, encrypt or change host authentication."""

import argparse
import importlib.util
import json
import shutil
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

SCRIPT = Path(__file__).resolve().parents[1] / "gateway-hardening.py"
SPEC = importlib.util.spec_from_file_location("gateway_hardening", SCRIPT)
hardening = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hardening)


class RefusalTests(unittest.TestCase):
    def arguments(self, **overrides):
        values = dict(backup_directory=None, recovery_confirmed=False,
                      root_device=None, boot_device=None, efi_device=None, root_uuid=None)
        values.update(overrides)
        return argparse.Namespace(**values)

    def test_absent_backup_refuses_before_privileged_operations(self):
        with patch.object(hardening, "run") as run, patch.object(hardening, "require_console") as console:
            with self.assertRaisesRegex(hardening.HardeningError, "BackupRequired"):
                hardening.encrypt_root(self.arguments())
            run.assert_not_called()
            console.assert_not_called()

    def test_installed_system_refuses_before_device_inspection(self):
        with patch.object(hardening, "require_console"), patch.object(hardening, "require_tools"), \
                patch.object(hardening, "run", return_value="ext4") as run, \
                patch.object(hardening, "validate_devices") as devices:
            with self.assertRaisesRegex(hardening.HardeningError, "LiveSystemRequired"):
                hardening.encrypt_root(self.arguments(backup_directory="/mnt/backup"))
            devices.assert_not_called()
            self.assertEqual(run.call_count, 1)

    def test_unprepared_recovery_refuses_on_live_system(self):
        with patch.object(hardening, "require_console"), patch.object(hardening, "require_tools"), \
                patch.object(hardening, "run", return_value="overlay"), \
                patch.object(hardening, "validate_devices") as devices, \
                patch.object(hardening.Path, "read_text", return_value="boot=casper"):
            with self.assertRaisesRegex(hardening.HardeningError, "RecoveryRequired"):
                hardening.encrypt_root(self.arguments(backup_directory="/mnt/backup"))
            devices.assert_not_called()

    def test_missing_device_selection_refuses(self):
        with patch.object(hardening, "require_console"), patch.object(hardening, "require_tools"), \
                patch.object(hardening, "run", return_value="overlay") as run, \
                patch.object(hardening.Path, "read_text", return_value="boot=casper"):
            with self.assertRaisesRegex(hardening.HardeningError, "DeviceSelectionRequired"):
                hardening.encrypt_root(self.arguments(backup_directory="/mnt/backup", recovery_confirmed=True))
            self.assertEqual(run.call_count, 1)

    def test_overlay_container_is_not_accepted_as_live_usb(self):
        with patch.object(hardening, "require_console"), patch.object(hardening, "require_tools"), \
                patch.object(hardening, "run", return_value="overlay"), \
                patch.object(hardening.Path, "read_text", return_value="root=/dev/sda"):
            with self.assertRaisesRegex(hardening.HardeningError, "LiveSystemRequired"):
                hardening.encrypt_root(self.arguments(backup_directory="/mnt/backup", recovery_confirmed=True))

    def test_firmware_recovery_refusal_never_reboots(self):
        with patch.object(hardening, "require_console"), patch.object(hardening, "run") as run:
            with self.assertRaisesRegex(hardening.HardeningError, "RecoveryRequired"):
                hardening.firmware(False)
            run.assert_not_called()

    def test_ssh_cannot_run_physical_operations(self):
        with patch.object(hardening.os, "geteuid", return_value=0), \
                patch.object(hardening.sys.stdin, "isatty", return_value=True), \
                patch.object(hardening.sys.stdout, "isatty", return_value=True), \
                patch.dict(hardening.os.environ, {"SSH_CONNECTION": "operator gateway"}):
            with self.assertRaisesRegex(hardening.HardeningError, "PhysicalConsoleRequired"):
                hardening.require_console(local=True)

    def test_sudo_cleared_environment_cannot_hide_ssh_ancestry(self):
        with patch.object(hardening.os, "geteuid", return_value=0), \
                patch.object(hardening.sys.stdin, "isatty", return_value=True), \
                patch.object(hardening.sys.stdout, "isatty", return_value=True), \
                patch.dict(hardening.os.environ, {}, clear=True), \
                patch.object(hardening, "ssh_ancestor", return_value=True):
            with self.assertRaisesRegex(hardening.HardeningError, "PhysicalConsoleRequired"):
                hardening.require_console(local=True)

    def test_boot_password_mismatch_never_writes_configuration(self):
        with patch.object(hardening, "require_console"), patch.object(hardening, "require_tools"), \
                patch.object(hardening.getpass, "getpass", side_effect=["a" * 24, "b" * 24]), \
                patch.object(hardening, "atomic_write") as write, \
                patch.object(hardening.subprocess, "run") as run:
            with self.assertRaisesRegex(hardening.HardeningError, "PassphraseRejected"):
                hardening.boot_password()
            write.assert_not_called()
            run.assert_not_called()

    def test_duplicate_devices_refuse_before_commands(self):
        with patch.object(hardening, "run") as run:
            with self.assertRaisesRegex(hardening.HardeningError, "DeviceCollision"):
                hardening.validate_devices("/dev/root", "/dev/root", "/dev/efi", "uuid")
            run.assert_not_called()

    def test_confirmation_mismatch_does_not_run_commands(self):
        with patch("builtins.input", return_value="wrong"), patch.object(hardening, "run") as run:
            with self.assertRaisesRegex(hardening.HardeningError, "ConfirmationMismatch"):
                hardening.confirm("target UUID")
            run.assert_not_called()


class FileSafetyTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("grub-mkpasswd-pbkdf2"), "native GRUB tool is not installed")
    def test_native_grub_hash_accepts_stdin_without_exposing_password(self):
        password = "test-only-passphrase-not-a-secret"
        result = subprocess.run(["grub-mkpasswd-pbkdf2", "-c", "600000"],
                                input=password + "\n" + password + "\n", text=True,
                                capture_output=True, timeout=15, check=False)
        self.assertEqual(result.returncode, 0)
        self.assertNotIn(password, result.stdout + result.stderr)
        self.assertRegex(result.stdout, r"grub\.pbkdf2\.sha512\.600000\.[0-9A-Fa-f]+\.[0-9A-Fa-f]+")

    def test_atomic_policy_replacement_uses_private_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy"
            path.write_text("previous\n")
            hardening.atomic_write(path, "new\n", 0o440)
            self.assertEqual(path.read_text(), "new\n")
            self.assertEqual(path.stat().st_mode & 0o777, 0o440)
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_policy_symlink_refused_without_modifying_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            target.write_text("unchanged")
            link = Path(directory) / "link"
            link.symlink_to(target)
            with self.assertRaisesRegex(hardening.HardeningError, "UnsafePath"):
                hardening.atomic_write(link, "changed")
            self.assertEqual(target.read_text(), "unchanged")

    def test_failed_unmount_never_removes_mounted_directory(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(hardening.tempfile, "mkdtemp", return_value=directory), \
                patch.object(hardening, "run") as run:
            run.side_effect = [None, hardening.HardeningError("unmount failed")]
            with self.assertRaisesRegex(hardening.HardeningError, "unmount failed"):
                with hardening.mounted("/dev/device"):
                    pass
            self.assertTrue(Path(directory).is_dir())

    def test_command_failure_stops_instead_of_downgrading(self):
        result = Mock(returncode=5, stdout="")
        with patch.object(hardening.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(hardening.HardeningError, "CommandFailed"):
                hardening.run("cryptsetup", "reencrypt")


class BackupSafetyTests(unittest.TestCase):
    def check_ancestry(self, nodes, expected_error=None, mapping_type="LUKS2"):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(hardening.Path, "stat", return_value=Mock(st_uid=0, st_mode=0o40700)), \
                patch.object(hardening.Path, "is_dir", return_value=True), \
                patch.object(hardening, "run") as run:
            run.side_effect = ["/dev/mapper/backup", json.dumps({"blockdevices": nodes}),
                               "nvme0n1", f"/dev/mapper/backup is active\n  type: {mapping_type}"]
            if expected_error:
                with self.assertRaisesRegex(hardening.HardeningError, expected_error):
                    hardening.validate_backup(directory, Path("/dev/nvme0n1p7"))
            else:
                self.assertEqual(hardening.validate_backup(directory, Path("/dev/nvme0n1p7")), Path(directory))

    def test_plaintext_backup_is_rejected(self):
        self.check_ancestry([{"name": "sdb1", "type": "part"}], "EncryptedBackupRequired")

    def test_encrypted_backup_on_system_disk_is_rejected(self):
        self.check_ancestry([{"name": "backup", "type": "crypt", "children":
                             [{"name": "nvme0n1", "type": "disk"}]}], "ExternalBackupRequired")

    def test_external_encrypted_backup_is_accepted(self):
        self.check_ancestry([{"name": "backup", "type": "crypt", "children":
                             [{"name": "sdb", "type": "disk"}]}])

    def test_plain_dm_crypt_is_not_accepted_as_luks_backup(self):
        self.check_ancestry([{"name": "backup", "type": "crypt", "children":
                             [{"name": "sdb", "type": "disk"}]}],
                            "EncryptedBackupRequired", mapping_type="PLAIN")


class AuthenticationPolicyTests(unittest.TestCase):
    def check_quality(self, main="", later="", module="retry=3", expected_error=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pam, conf = root / "common-password", root / "pwquality.conf"
            snippets = root / "conf.d"
            snippets.mkdir()
            pam.write_text(f"password requisite pam_pwquality.so {module}\n")
            conf.write_text(main)
            (snippets / "00-distribution.conf").write_text("minlen = 8\n")
            (snippets / "zzz-local.conf").write_text(later)
            if expected_error:
                with self.assertRaisesRegex(hardening.HardeningError, expected_error):
                    hardening.validate_password_quality(pam, snippets, conf)
            else:
                hardening.validate_password_quality(pam, snippets, conf)

    def test_standard_pam_accepts_strong_policy(self):
        self.check_quality()

    def test_main_file_cannot_override_minimum_length(self):
        self.check_quality(main="minlen = 8\n", expected_error="ConflictingPasswordQuality")

    def test_later_snippet_cannot_disable_enforcement(self):
        self.check_quality(later="enforcing = 0\n", expected_error="ConflictingPasswordQuality")

    def test_pam_argument_cannot_disable_enforcement(self):
        self.check_quality(module="retry=3 enforcing=0", expected_error="ConflictingPasswordQuality")

    def test_alternate_pam_configuration_is_rejected(self):
        self.check_quality(module="conf=/tmp/weak.conf", expected_error="ConflictingPasswordQuality")

    def test_passwordless_sudo_never_reaches_interactive_validation(self):
        with patch.object(hardening, "run") as run, \
                patch.object(hardening.subprocess, "run", return_value=Mock(returncode=0)):
            with self.assertRaisesRegex(hardening.HardeningError, "ConflictingSudoPolicy"):
                hardening.verify_sudo_password("operator")
            self.assertEqual(run.call_count, 1)

    def test_sudo_requires_fresh_password_validation(self):
        with patch.object(hardening, "run") as run, \
                patch.object(hardening.subprocess, "run", return_value=Mock(returncode=1)):
            hardening.verify_sudo_password("operator")
            self.assertEqual(run.call_args.args, ("runuser", "-u", "operator", "--", "sudo", "-k", "-v"))

    def test_ssh_match_override_is_rejected(self):
        effective = "permitrootlogin no\npubkeyauthentication yes\npasswordauthentication no\n" \
                    "kbdinteractiveauthentication no\nauthenticationmethods publickey\ndisableforwarding yes\n"
        with patch.dict(hardening.os.environ, {"SSH_CONNECTION": "192.0.2.2 1234 192.0.2.1 22"}), \
                patch.object(hardening, "run", side_effect=[effective, effective.replace(
                    "passwordauthentication no", "passwordauthentication yes")]) as run:
            with self.assertRaisesRegex(hardening.HardeningError, "ConflictingSshPolicy"):
                hardening.verify_ssh_policy("operator")
            self.assertIn("user=operator,addr=192.0.2.2", run.call_args.args[-1])


class RootLayoutTests(unittest.TestCase):
    def check_layout(self, fstab=None, crypttab="", expected_error=None, symlink_boot=False):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            for relative in ("etc", "boot/efi", "dev", "proc", "sys", "run"):
                (source / relative).mkdir(parents=True, exist_ok=True)
            (source / "etc/fstab").write_text(fstab if fstab is not None else
                "UUID=root / ext4 defaults 0 1\nUUID=efi /boot/efi vfat umask=0077 0 1\n"
                "/swap.img none swap sw 0 0\n")
            (source / "etc/crypttab").write_text(crypttab)
            if symlink_boot:
                (source / "boot").rename(source / "other-boot")
                (source / "boot").symlink_to(source / "other-boot")
            if expected_error:
                with self.assertRaisesRegex(hardening.HardeningError, expected_error):
                    hardening.validate_root_layout(source, "root", "efi")
            else:
                hardening.validate_root_layout(source, "root", "efi")

    def test_root_and_efi_with_enclosed_swap_are_supported(self):
        self.check_layout()

    def test_an_existing_separate_boot_partition_is_rejected(self):
        self.check_layout("UUID=root / ext4 defaults 0 1\nUUID=efi /boot/efi vfat defaults 0 1\n"
                          "UUID=old-boot /boot ext4 defaults 0 2\n", expected_error="UnsupportedMountLayout")

    def test_wrong_efi_partition_is_rejected(self):
        self.check_layout("UUID=root / ext4 defaults 0 1\nUUID=windows-efi /boot/efi vfat defaults 0 1\n",
                          expected_error="EfiMountMismatch")

    def test_existing_crypt_mapping_is_rejected_before_migration(self):
        self.check_layout(crypttab="helios-root UUID=existing none luks\n", expected_error="UnsupportedCrypttab")

    def test_symlink_boot_is_rejected(self):
        self.check_layout(symlink_boot=True, expected_error="UnsupportedMountLayout")


class AuthenticationTransactionTests(unittest.TestCase):
    def exercise_auth(self, sudo_failure=False, ssh_failure=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            originals = {
                "etc/sudoers.d/helios-test-phase": "operator ALL=(ALL) NOPASSWD: ALL\n",
                "etc/sudoers.d/helios-target-tests": "operator ALL=(ALL) NOPASSWD: /bin/true\n",
                "etc/sudoers.d/zz-helios-auth": "# original sudo policy\n",
                "etc/ssh/sshd_config.d/00-helios-hardening.conf": "# original SSH policy\n",
                "etc/pam.d/common-password": "password requisite pam_pwquality.so retry=3\n",
                "etc/pam.d/passwd": "@include common-password\n",
                "home/operator/.ssh/authorized_keys": "test public key\n",
            }
            for relative, contents in originals.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(contents)
            (root / "var/lib").mkdir(parents=True)
            (root / "etc/security").mkdir()
            def local_path(value):
                path = Path(value)
                return root / str(path).lstrip("/") if not path.is_relative_to(root) else path
            commands = []
            def command(*args, **kwargs):
                commands.append(args)
                if args[0] == "id":
                    return "operator sudo"
                if ssh_failure and args == ("systemctl", "reload", "ssh") and commands.count(args) == 1:
                    raise hardening.HardeningError("reload failed")
                return ""
            def verify_sudo(user):
                if sudo_failure:
                    raise hardening.HardeningError("password rejected")
            with patch.object(hardening, "Path", side_effect=local_path), \
                    patch.object(hardening, "require_console"), \
                    patch.object(hardening, "require_tools"), \
                    patch.object(hardening, "ssh_ancestor", return_value=False), \
                    patch.object(hardening.pwd, "getpwnam", return_value=Mock(pw_uid=1000, pw_dir="/home/operator")), \
                    patch.object(hardening, "run", side_effect=command), \
                    patch.object(hardening, "verify_sudo_password", side_effect=verify_sudo), \
                    patch.object(hardening, "verify_ssh_policy"), \
                    patch("builtins.print"):
                if sudo_failure or ssh_failure:
                    with self.assertRaisesRegex(hardening.HardeningError,
                                                "AuthRollback" if sudo_failure else "SshRollback"):
                        hardening.auth("operator")
                else:
                    hardening.auth("operator")
            if sudo_failure:
                for relative, contents in originals.items():
                    if relative.startswith("etc/sudoers.d"):
                        self.assertEqual((root / relative).read_text(), contents)
                self.assertNotIn(("passwd", "-l", "root"), commands)
                self.assertNotIn(("systemctl", "reload", "ssh"), commands)
            else:
                self.assertIn("PASSWD: ALL", (root / "etc/sudoers.d/zz-helios-auth").read_text())
                for name in ("helios-test-phase", "helios-target-tests"):
                    self.assertFalse((root / "etc/sudoers.d" / name).exists())
                    saved = list((root / "var/lib/helios-host-hardening").glob(f"auth-*/{name}"))
                    self.assertEqual(len(saved), 1)
                    self.assertEqual(saved[0].read_text(), originals[f"etc/sudoers.d/{name}"])
                if ssh_failure:
                    path = "etc/ssh/sshd_config.d/00-helios-hardening.conf"
                    self.assertEqual((root / path).read_text(), originals[path])
                    self.assertEqual(commands.count(("systemctl", "reload", "ssh")), 2)
                else:
                    self.assertIn("PasswordAuthentication no", (root /
                        "etc/ssh/sshd_config.d/00-helios-hardening.conf").read_text())

    def test_rejected_password_restores_sudo_exemptions_and_policy(self):
        self.exercise_auth(sudo_failure=True)

    def test_failed_ssh_reload_restores_ssh_and_keeps_validated_sudo(self):
        self.exercise_auth(ssh_failure=True)

    def test_success_keeps_private_backups_and_hardened_policies(self):
        self.exercise_auth()


if __name__ == "__main__":
    unittest.main()
