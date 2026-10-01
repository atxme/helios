#!/usr/bin/env python3
"""Local gateway authentication and offline Linux root encryption.

Passwords are collected only by native interactive tools. Firmware settings
remain an operator action; entering setup does not enable Secure Boot.
"""

import argparse
import contextlib
import getpass
import json
import math
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile


class HardeningError(Exception):
    """An explicit refusal or failed operation, safe to show to the operator."""


SSH_POLICY = """# Helios gateway: administrative access uses public keys only.
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
PermitEmptyPasswords no
DisableForwarding yes
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
AllowStreamLocalForwarding no
MaxAuthTries 3
LoginGraceTime 30
"""

PASSWORD_QUALITY = """# Helios operator passphrases; use the existing PAM pwquality module.
minlen = 20
dcredit = 0
ucredit = 0
lcredit = 0
ocredit = 0
maxrepeat = 3
dictcheck = 1
usercheck = 1
enforcing = 1
enforce_for_root
"""


def fail(code, message):
    raise HardeningError(f"{code}: {message}")


def run(*args, capture=False, allowed=(0,)):
    result = subprocess.run(
        args, check=False, text=True,
        stdout=subprocess.PIPE if capture else None,
        env={**os.environ, "LC_ALL": "C"},
    )
    if result.returncode not in allowed:
        fail("CommandFailed", f"{args[0]} exited with {result.returncode}; stop and inspect")
    return result.stdout.strip() if capture else None


def require_tools(*names):
    for name in names:
        if shutil.which(name) is None:
            fail("MissingTool", f"install {name} before this operation")


def ssh_ancestor():
    process = os.getpid()
    seen = set()
    while process > 1:
        if process in seen:
            fail("ConsoleOriginUnknown", "cannot establish a local process ancestry")
        seen.add(process)
        try:
            fields = dict(line.split(":", 1) for line in
                          Path(f"/proc/{process}/status").read_text().splitlines() if ":" in line)
            if fields["Name"].strip().startswith("sshd"):
                return True
            process = int(fields["PPid"].strip())
        except (OSError, KeyError, ValueError):
            fail("ConsoleOriginUnknown", "cannot establish a local process ancestry")
    return False


def require_console(local=False):
    if os.geteuid() != 0:
        fail("RootRequired", "run with sudo")
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        fail("TerminalRequired", "use an interactive terminal; no passwords in arguments")
    if local and (os.environ.get("SSH_CONNECTION") or os.environ.get("SSH_TTY") or ssh_ancestor()):
        fail("PhysicalConsoleRequired", "run locally in front of the gateway")
    if "microsoft" in Path("/proc/sys/kernel/osrelease").read_text().lower():
        fail("TargetRequired", "this operation cannot run under WSL")


def confirm(text):
    if input(f"Type {text!r} to continue: ") != text:
        fail("ConfirmationMismatch", "nothing further was changed")


def atomic_write(path, content, mode=0o600):
    path = Path(path)
    if path.is_symlink():
        fail("UnsafePath", f"refusing symbolic link: {path}")
    descriptor, temporary = tempfile.mkstemp(prefix=".helios-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def audit():
    require_tools("findmnt", "lsblk", "mokutil")
    run("findmnt", "-no", "SOURCE,FSTYPE,OPTIONS", "/")
    run("lsblk", "-e", "7", "-o", "NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS")
    run("mokutil", "--sb-state")
    print("Encryption requires an external encrypted backup, tested Helios recovery,")
    print("a live USB console, and a separate empty ext4 /boot partition.")
    print("No disk or firmware setting was changed.")


def validate_password_quality(pam_path, quality_directory, main_configuration):
    lines = [line.strip() for line in pam_path.read_text().splitlines()
             if line.strip() and not line.lstrip().startswith("#")]
    modules = [line for line in lines if "pam_pwquality.so" in line]
    if len(modules) != 1 or not re.match(
            r"^password\s+requisite\s+pam_pwquality\.so(?:\s|$)", modules[0]):
        fail("PasswordQualityRequired", "enable the standard Ubuntu pwquality PAM profile first")
    # Module arguments take precedence over configuration files. Only the
    # standard retry option is supported; reject alternate config/soft checks.
    if any(not re.fullmatch(r"retry=[1-9][0-9]*", option)
           for option in modules[0].split()[3:]):
        fail("ConflictingPasswordQuality", "review explicit pwquality PAM overrides first")
    def settings(content):
        result = {}
        for line in content.splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                key, separator, value = line.partition("=")
                result[key.strip()] = value.strip() if separator else ""
        return result
    expected = settings(PASSWORD_QUALITY)
    files = {path.name: path for path in quality_directory.glob("*.conf")}
    files["zz-helios.conf"] = None
    effective = {}
    for name in sorted(files):
        effective.update(expected if files[name] is None else settings(files[name].read_text()))
    # libpwquality reads the main file AFTER all conf.d snippets.
    if main_configuration.exists():
        effective.update(settings(main_configuration.read_text()))
    if any(effective.get(key) != value for key, value in expected.items()):
        fail("ConflictingPasswordQuality", "a later pwquality setting overrides the Helios policy")


def verify_sudo_password(user):
    run("runuser", "-u", user, "--", "sudo", "-k")
    result = subprocess.run(["runuser", "-u", user, "--", "sudo", "-n", "-v"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    if result.returncode == 0:
        fail("ConflictingSudoPolicy", "sudo still authenticates without the operator password")
    if result.returncode != 1:
        fail("SudoProbeFailed", "cannot verify non-interactive sudo refusal")
    run("runuser", "-u", user, "--", "sudo", "-k", "-v")


def verify_ssh_policy(user):
    required = {"permitrootlogin": "no", "pubkeyauthentication": "yes",
                "passwordauthentication": "no", "kbdinteractiveauthentication": "no",
                "authenticationmethods": "publickey", "disableforwarding": "yes"}
    commands = [("sshd", "-T")]
    connection = os.environ.get("SSH_CONNECTION")
    if connection:
        fields = connection.split()
        if len(fields) != 4:
            fail("SshContextUnknown", "cannot validate the current SSH connection")
        address, _, local_address, local_port = fields
        # Include user/address Match blocks for the connection being hardened.
        commands.append(("sshd", "-T", "-C",
                         f"user={user},addr={address},host={address},"
                         f"laddr={local_address},lport={local_port}"))
    for command in commands:
        effective = dict(line.split(None, 1) for line in run(*command, capture=True).splitlines())
        if any(effective.get(key) != value for key, value in required.items()):
            fail("ConflictingSshPolicy", "another configuration overrides key-only authentication")


def auth(user):
    require_console()
    if ssh_ancestor() and not os.environ.get("SSH_CONNECTION"):
        fail("SshContextRequired", "preserve SSH_CONNECTION through sudo before hardening remote access")
    require_tools("passwd", "visudo", "runuser", "sudo", "sshd", "ssh-keygen", "id", "systemctl")
    if not re.fullmatch(r"[a-z_][a-z0-9_-]*", user):
        fail("InvalidUser", "use an existing non-root administrator account")
    account = pwd.getpwnam(user)
    if account.pw_uid == 0:
        fail("InvalidUser", "root is not the operator account")
    groups = run("id", "-nG", user, capture=True).split()
    if "sudo" not in groups:
        fail("AdministratorRequired", "account must already belong to sudo")
    authorized = Path(account.pw_dir) / ".ssh/authorized_keys"
    if not authorized.is_file():
        fail("AuthorizedKeyRequired", "install and test an operator public key first")
    run("ssh-keygen", "-l", "-f", str(authorized), capture=True)
    exceptions = [Path("/etc/sudoers.d") / name for name in
                  ("helios-test-phase", "helios-target-tests")]
    for path in exceptions:
        if not path.exists():
            continue
        if path.is_symlink():
            fail("UnsafePath", f"refusing symbolic link: {path}")
        lines = [line.strip() for line in path.read_text().splitlines()
                 if line.strip() and not line.lstrip().startswith("#")]
        if any(not line.startswith(f"{user} ALL=") for line in lines):
            fail("UnexpectedSudoPolicy", f"inspect {path}; other accounts or rules are present")
    run("visudo", "-c")
    quality_directory = Path("/etc/security/pwquality.conf.d")
    passwd_pam = [line.strip() for line in Path("/etc/pam.d/passwd").read_text().splitlines()
                  if line.strip() and not line.lstrip().startswith("#")]
    if passwd_pam != ["@include common-password"]:
        fail("PasswordQualityRequired", "passwd must use the standard Ubuntu common-password stack")
    validate_password_quality(Path("/etc/pam.d/common-password"), quality_directory,
                              Path("/etc/security/pwquality.conf"))
    quality_directory.mkdir(mode=0o755, exist_ok=True)
    atomic_write(quality_directory / "zz-helios.conf", PASSWORD_QUALITY, 0o644)
    print("Choose a unique long passphrase. passwd collects it without logging it.")
    run("passwd", user)
    policy = Path("/etc/sudoers.d/zz-helios-auth")
    previous = policy.read_text() if policy.exists() else None
    if policy.is_symlink():
        fail("UnsafePath", f"refusing symbolic link: {policy}")
    backup = Path("/var/lib/helios-host-hardening")
    if backup.exists() and (backup.is_symlink() or backup.stat().st_uid != 0
                            or backup.stat().st_mode & 0o077):
        fail("UnsafePath", "hardening backup directory must be private and root-owned")
    backup.mkdir(mode=0o700, exist_ok=True)
    transaction = Path(tempfile.mkdtemp(prefix="auth-", dir=backup))
    moved = []
    try:
        for path in exceptions:
            if path.exists():
                destination = transaction / path.name
                os.rename(path, destination)
                moved.append((path, destination))
        # PASSWD explicitly overrides a remaining exemption for this operator;
        # the account already has ALL privileges via its existing sudo group.
        atomic_write(policy, f"Defaults:{user} timestamp_timeout=15\n"
                     f"{user} ALL=(ALL:ALL) PASSWD: ALL\n", 0o440)
        run("visudo", "-c")
        print("Verify the new password as the operator before retaining the sudo policy.")
        verify_sudo_password(user)
    except (HardeningError, KeyboardInterrupt, OSError):
        if previous is None:
            policy.unlink(missing_ok=True)
        else:
            atomic_write(policy, previous, 0o440)
        for original, saved in moved:
            os.rename(saved, original)
        run("visudo", "-c")
        fail("AuthRollback", "sudo policy restored; the new account password remains in effect")
    run("passwd", "-l", "root")
    ssh_policy = Path("/etc/ssh/sshd_config.d/00-helios-hardening.conf")
    previous_ssh = ssh_policy.read_text() if ssh_policy.exists() else None
    try:
        atomic_write(ssh_policy, SSH_POLICY, 0o644)
        run("sshd", "-t")
        verify_ssh_policy(user)
        run("systemctl", "reload", "ssh")
    except (HardeningError, KeyboardInterrupt, OSError):
        if previous_ssh is None:
            ssh_policy.unlink(missing_ok=True)
        else:
            atomic_write(ssh_policy, previous_ssh, 0o644)
        run("sshd", "-t")
        run("systemctl", "reload", "ssh")
        fail("SshRollback", "SSH policy restored; password and authenticated sudo changes remain in effect")
    print("Password changed, root password locked, sudo requires the operator password.")
    print("Sudo authentication is cached for 15 minutes in the same terminal.")
    print("SSH accepts public keys only; root login and forwarding are disabled.")
    print("Keep this session open until a second key connection is verified.")


def validate_devices(root, boot, efi, expected_uuid):
    devices = [Path(value).resolve() for value in (root, boot, efi)]
    if len(set(devices)) != 3:
        fail("DeviceCollision", "root, boot and EFI must be distinct partitions")
    for device, filesystem in zip(devices, ("ext4", "ext4", "vfat")):
        if not stat.S_ISBLK(device.stat().st_mode):
            fail("BlockDeviceRequired", f"not a block device: {device}")
        if run("lsblk", "-dn", "-o", "TYPE", str(device), capture=True) != "part":
            fail("PartitionRequired", "whole disks must never be passed to this script")
        if run("lsblk", "-nr", "-o", "TYPE", str(device), capture=True).split() != ["part"]:
            fail("ActiveMapping", f"close any active block mapping for {device} first")
        if run("blkid", "-s", "TYPE", "-o", "value", str(device), capture=True) != filesystem:
            fail("UnexpectedFilesystem", f"{device} must already contain {filesystem}")
        mounts = run("lsblk", "-nr", "-o", "MOUNTPOINTS", str(device), capture=True)
        if mounts:
            fail("MountedTarget", f"unmount {device} and its children first")
    uuid = run("blkid", "-s", "UUID", "-o", "value", str(devices[0]), capture=True)
    if uuid != expected_uuid:
        fail("IdentityMismatch", "root filesystem UUID differs from the audited target")
    return devices


def validate_backup(directory, root):
    if directory is None:
        fail("BackupRequired", "supply a directory on an external unlocked LUKS disk")
    directory = Path(directory).resolve(strict=True)
    if not directory.is_dir():
        fail("BackupRequired", "backup destination must be an existing directory")
    for ancestor in [directory, *directory.parents]:
        metadata = ancestor.stat()
        if metadata.st_uid != 0 or metadata.st_mode & 0o022:
            fail("UnsafeBackupPath", "backup path must be root-owned, without group/other writes")
    source = run("findmnt", "-no", "SOURCE", "-T", str(directory), capture=True)
    if not source.startswith("/dev/"):
        fail("EncryptedBackupRequired", "use a local external LUKS device")
    ancestry = json.loads(run("lsblk", "-sJ", "-o", "NAME,TYPE", source, capture=True))
    def flatten(nodes):
        for node in nodes:
            yield node
            yield from flatten(node.get("children", []))
    nodes = list(flatten(ancestry["blockdevices"]))
    encrypted = [node for node in nodes if node["type"] == "crypt"]
    if not encrypted:
        fail("EncryptedBackupRequired", "backup filesystem has no active LUKS layer")
    parent = run("lsblk", "-dn", "-o", "PKNAME", str(root), capture=True)
    if not parent or "/" in parent or len(parent.split()) != 1:
        fail("SystemDiskUnknown", "cannot identify the root partition's physical disk")
    if any(node["name"] == parent for node in nodes):
        fail("ExternalBackupRequired", "backup must not reside on the gateway system disk")
    for node in encrypted:
        status = run("cryptsetup", "status", node["name"], capture=True)
        fields = {key.strip(): value.strip() for key, value in
                  (line.split(":", 1) for line in status.splitlines() if ":" in line)}
        if fields.get("type") not in ("LUKS1", "LUKS2"):
            fail("EncryptedBackupRequired", "backup mapping must use LUKS, not plain dm-crypt")
    return directory


def validate_root_layout(source, root_uuid, efi_uuid):
    for relative in ("etc", "etc/fstab", "boot", "boot/efi", "dev", "proc", "sys", "run"):
        path = source / relative
        if not path.exists() or path.is_symlink():
            fail("UnsupportedMountLayout", f"expected an existing non-symlink {relative}")
    entries = []
    for line in (source / "etc/fstab").read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        fields = line.split()
        if len(fields) != 6:
            fail("UnsupportedMountLayout", "fstab entries must contain all six fields")
        entries.append(fields)
    roots = [fields for fields in entries if fields[1] == "/"]
    esp = [fields for fields in entries if fields[1] == "/boot/efi"]
    if len(roots) != 1 or roots[0][:3] != [f"UUID={root_uuid}", "/", "ext4"]:
        fail("RootMountMismatch", "fstab root must match the selected ext4 UUID")
    if len(esp) != 1 or esp[0][:3] != [f"UUID={efi_uuid}", "/boot/efi", "vfat"]:
        fail("EfiMountMismatch", "fstab EFI must match the selected FAT UUID")
    for fields in entries:
        if fields[1] not in ("/", "/boot/efi") and fields[:3] != ["/swap.img", "none", "swap"]:
            fail("UnsupportedMountLayout", "only root, EFI and optional swap.img are supported; /boot must be inside root")
    crypttab = source / "etc/crypttab"
    if crypttab.is_symlink() or (crypttab.exists() and any(
            line.split("#", 1)[0].strip() for line in crypttab.read_text().splitlines())):
        fail("UnsupportedCrypttab", "review existing crypt mappings before migration")


@contextlib.contextmanager
def mounted(device, readonly=False):
    directory = Path(tempfile.mkdtemp(prefix="helios-mount-", dir="/run"))
    active = False
    try:
        run("mount", "-o", "ro,noload" if readonly and
            run("blkid", "-s", "TYPE", "-o", "value", str(device), capture=True) == "ext4"
            else "ro" if readonly else "rw", str(device), str(directory))
        active = True
        yield directory
    finally:
        if active:
            # Never delete a directory while a filesystem is still mounted.
            run("umount", str(directory))
        directory.rmdir()


def encrypt_root(args):
    # Refuse absent backups before touching devices or changing any filesystem.
    if not args.backup_directory:
        fail("BackupRequired", "no conversion is permitted without an external encrypted backup")
    require_console(local=True)
    require_tools("cryptsetup", "e2fsck", "resize2fs", "tune2fs", "lsblk", "blkid",
                  "findmnt", "mount", "umount", "tar", "sha256sum", "sfdisk", "chroot", "cp", "du", "sync")
    if run("findmnt", "-no", "FSTYPE", "/", capture=True) != "overlay":
        fail("LiveSystemRequired", "boot a Linux live USB; installed root must remain unmounted")
    if "boot=casper" not in Path("/proc/cmdline").read_text().split():
        fail("LiveSystemRequired", "use Ubuntu live media; an overlay container is not a live USB")
    if not args.recovery_confirmed:
        fail("RecoveryRequired", "prepare and test Helios recovery before changing its boot chain")
    if not all((args.root_device, args.boot_device, args.efi_device, args.root_uuid)):
        fail("DeviceSelectionRequired", "explicit root, empty ext4 boot, EFI and root UUID are required")
    root, boot, efi = validate_devices(args.root_device, args.boot_device,
                                      args.efi_device, args.root_uuid)
    backup_directory = validate_backup(args.backup_directory, root)
    if Path("/dev/mapper/helios-root").exists():
        fail("MapperExists", "close the pre-existing helios-root mapping first")
    run("e2fsck", "-f", "-n", str(root))
    with mounted(root, readonly=True) as source, mounted(boot, readonly=True) as boot_path:
        if any(entry.name != "lost+found" for entry in boot_path.iterdir()):
            fail("BootNotEmpty", "the separate boot filesystem must be empty; nothing is erased here")
        if not (source / "etc/os-release").exists() or not (source / "var/lib/helios/network.toml").exists():
            fail("NotHeliosRoot", "selected partition is not the installed Helios system")
        efi_uuid = run("blkid", "-s", "UUID", "-o", "value", str(efi), capture=True)
        validate_root_layout(source, args.root_uuid, efi_uuid)
        # Install these on the gateway BEFORE the backup and offline operation.
        # Depending on a later download would risk an encrypted but unbootable root.
        status = run("chroot", str(source), "dpkg-query", "-W",
                     "-f=${Status}", "cryptsetup-initramfs", capture=True, allowed=(0, 1))
        if status != "install ok installed":
            fail("InitramfsDependencyRequired", "install cryptsetup-initramfs on the gateway before migration")
        used = (os.statvfs(source).f_blocks - os.statvfs(source).f_bfree) * os.statvfs(source).f_frsize
        free = os.statvfs(backup_directory).f_bavail * os.statvfs(backup_directory).f_frsize
        if free < used + 2 * 1024**3:
            fail("BackupSpaceRequired", "external disk needs used root space plus 2 GiB")
        boot_used = int(run("du", "-sb", str(source / "boot"), capture=True).split()[0])
        boot_free = os.statvfs(boot_path).f_bavail * os.statvfs(boot_path).f_frsize
        if boot_free < boot_used + 512 * 1024**2:
            fail("BootSpaceRequired", "empty boot partition needs current boot files plus 512 MiB")
        confirm(f"BACKUP AND ENCRYPT {args.root_uuid}")
        backup = Path(tempfile.mkdtemp(prefix="helios-root-", dir=backup_directory))
        run("tar", "--xattrs", "--acls", "--numeric-owner", "--sparse", "--one-file-system",
            "-cpf", str(backup / "root.tar"), "-C", str(source), ".")
        # Compare file contents to the offline source without logging paths.
        with open(os.devnull, "w") as sink:
            result = subprocess.run(["tar", "--xattrs", "--acls", "--compare", "-f",
                                     str(backup / "root.tar"), "-C", str(source)],
                                    stdout=sink, stderr=sink, check=False)
        if result.returncode:
            fail("BackupMismatch", "archive differs from the offline source; root was not converted")
    with mounted(efi, readonly=True) as efi_path:
        if not all((efi_path / "EFI/ubuntu" / name).is_file()
                   for name in ("shimx64.efi", "grubx64.efi", "grub.cfg")):
            fail("UbuntuEfiRequired", "the ESP must contain the existing Ubuntu shim/GRUB installation")
        run("tar", "-cpf", str(backup / "efi.tar"), "-C", str(efi_path), ".")
    parent = run("lsblk", "-dn", "-o", "PKNAME", str(root), capture=True)
    atomic_write(backup / "partition-table.txt", run("sfdisk", "--dump", f"/dev/{parent}", capture=True) + "\n")
    with (backup / "SHA256SUMS").open("w") as stream:
        result = subprocess.run(["sha256sum", "root.tar", "efi.tar", "partition-table.txt"],
                                cwd=backup, stdout=stream, check=False)
    if result.returncode:
        fail("BackupChecksumFailed", "root was not converted")
    run("sync")
    print(f"Backup saved on the external encrypted disk: {backup}")
    # Copy /boot before encryption; EFI is retained without formatting.
    with mounted(root, readonly=True) as source, mounted(boot) as boot_path:
        run("cp", "-a", str(source / "boot") + "/.", str(boot_path))
        run("sync")
    run("e2fsck", "-f", "-p", str(root), allowed=(0, 1))
    metadata = run("tune2fs", "-l", str(root), capture=True)
    fields = dict(line.split(":", 1) for line in metadata.splitlines() if ":" in line)
    blocks, block_size = int(fields["Block count"]), int(fields["Block size"])
    reduced = blocks - math.ceil(32 * 1024**2 / block_size)
    if reduced <= 0:
        fail("RootTooSmall", "root filesystem cannot accommodate the LUKS header")
    run("resize2fs", str(root), str(reduced))
    print("Enter a unique long LUKS passphrase in the native cryptsetup prompt.")
    run("cryptsetup", "reencrypt", "--encrypt", "--type", "luks2", "--pbkdf", "argon2id",
        "--cipher", "aes-xts-plain64", "--key-size", "512",
        "--reduce-device-size", "32M", "--verify-passphrase", str(root))
    run("cryptsetup", "luksHeaderBackup", str(root), "--header-backup-file", str(backup / "luks-header.img"))
    run("sync")
    run("cryptsetup", "open", str(root), "helios-root")
    try:
        run("resize2fs", "/dev/mapper/helios-root")
        with mounted("/dev/mapper/helios-root") as target:
            nested = []
            try:
                for device, relative in ((boot, "boot"), (efi, "boot/efi")):
                    location = target / relative
                    location.mkdir(parents=True, exist_ok=True)
                    run("mount", str(device), str(location))
                    nested.append(location)
                crypt_uuid = run("cryptsetup", "luksUUID", str(root), capture=True)
                crypttab = target / "etc/crypttab"
                original = crypttab.read_text() if crypttab.exists() else ""
                if any(line.split()[0] == "helios-root" for line in original.splitlines()
                       if line.strip() and not line.lstrip().startswith("#")):
                    fail("CrypttabCollision", "existing helios-root entry needs manual review")
                atomic_write(crypttab, original.rstrip() + "\n" +
                             f"helios-root UUID={crypt_uuid} none luks,initramfs\n")
                fstab = target / "etc/fstab"
                retained = [line for line in fstab.read_text().splitlines()
                            if not line.strip() or line.lstrip().startswith("#") or
                            len(line.split()) < 2 or line.split()[1] not in ("/", "/boot", "/boot/efi")]
                boot_uuid = run("blkid", "-s", "UUID", "-o", "value", str(boot), capture=True)
                efi_uuid = run("blkid", "-s", "UUID", "-o", "value", str(efi), capture=True)
                retained += [f"UUID={args.root_uuid} / ext4 defaults 0 1",
                             f"UUID={boot_uuid} /boot ext4 defaults 0 2",
                             f"UUID={efi_uuid} /boot/efi vfat umask=0077 0 1"]
                atomic_write(fstab, "\n".join(retained) + "\n", 0o644)
                # Ubuntu's EFI stub still searches the old unencrypted root.
                # Point it at the new plaintext /boot without replacing signed
                # shim/GRUB binaries or changing Windows/NVRAM boot entries.
                atomic_write(target / "boot/efi/EFI/ubuntu/grub.cfg",
                             f"search --no-floppy --fs-uuid --set=root {boot_uuid}\n"
                             "set prefix=($root)/grub\nconfigfile $prefix/grub.cfg\n", 0o600)
                for relative in ("dev", "proc", "sys", "run"):
                    location = target / relative
                    run("mount", "--rbind", f"/{relative}", str(location))
                    nested.append(location)
                    run("mount", "--make-rslave", str(location))
                run("chroot", str(target), "update-initramfs", "-u", "-k", "all")
                run("chroot", str(target), "update-grub")
                run("sync")
            finally:
                for location in reversed(nested):
                    run("umount", "-R", str(location))
    finally:
        run("cryptsetup", "close", "helios-root")
    print("Linux root converted to LUKS2; swap.img resides inside the encrypted root.")
    print("Windows partitions and EFI boot entries were not reformatted or deleted.")
    print("Do not erase the backup. Perform the local boot and Helios recovery checks.")
    print("Keep Secure Boot configuration and GRUB console authentication in the maintenance procedure.")


def firmware(recovery_confirmed):
    require_console(local=True)
    if not recovery_confirmed:
        fail("RecoveryRequired", "test recovery of Helios identities before changing PCR 7")
    print("In firmware: enable Secure Boot, set an administrator password,")
    print("disable unused external/PXE boot, and retain the Ubuntu shim boot entry.")
    print("This script cannot set these vendor-specific firmware options.")
    confirm("ENTER FIRMWARE SETUP")
    run("systemctl", "reboot", "--firmware-setup")


def boot_password():
    require_console(local=True)
    require_tools("grub-mkpasswd-pbkdf2", "update-grub")
    password = getpass.getpass("New GRUB administrator passphrase (at least 20 characters): ")
    if len(password) < 20 or password != getpass.getpass("Repeat passphrase: "):
        fail("PassphraseRejected", "passphrases must match and contain at least 20 characters")
    # Native GRUB hashing; neither plaintext nor its hash enters argv or logs.
    result = subprocess.run(["grub-mkpasswd-pbkdf2", "-c", "600000"],
                            input=password + "\n" + password + "\n",
                            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    del password
    match = re.search(r"grub\.pbkdf2\.sha512\.600000\.[0-9A-Fa-f]+\.[0-9A-Fa-f]+", result.stdout)
    if result.returncode or not match:
        fail("GrubHashFailed", "no verified GRUB password hash was produced")
    script = Path("/etc/grub.d/01_helios_auth")
    defaults = Path("/etc/default/grub.d/99-helios-auth.cfg")
    if script.exists() or defaults.exists():
        fail("ExistingBootAuth", "inspect the existing boot authentication before replacing it")
    if not defaults.parent.is_dir():
        fail("GrubLayoutRequired", "expected /etc/default/grub.d directory")
    try:
        atomic_write(script, '#!/bin/sh\ncat <<\'GRUB_AUTH\'\nset superusers="helios-admin"\n'
                     f'export superusers\npassword_pbkdf2 helios-admin {match.group()}\nGRUB_AUTH\n', 0o700)
        atomic_write(defaults, "GRUB_DISABLE_RECOVERY=true\n", 0o600)
        run("update-grub")
        os.chmod("/boot/grub/grub.cfg", 0o600)
    except (HardeningError, KeyboardInterrupt, OSError):
        script.unlink(missing_ok=True)
        defaults.unlink(missing_ok=True)
        run("update-grub")
        fail("BootAuthRollback", "boot authentication configuration restored")
    print("GRUB administrator is helios-admin; editing and protected boot entries require its passphrase.")
    print("Test locally before leaving. This may require authentication on each reboot.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("audit")
    commands.add_parser("boot-password")
    auth_parser = commands.add_parser("auth")
    auth_parser.add_argument("--user", required=True)
    firmware_parser = commands.add_parser("firmware")
    firmware_parser.add_argument("--recovery-confirmed", action="store_true")
    encrypt = commands.add_parser("encrypt-root")
    for name in ("root-device", "boot-device", "efi-device", "root-uuid", "backup-directory"):
        encrypt.add_argument(f"--{name}")
    encrypt.add_argument("--recovery-confirmed", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "audit":
            audit()
        elif args.command == "boot-password":
            boot_password()
        elif args.command == "auth":
            auth(args.user)
        elif args.command == "firmware":
            firmware(args.recovery_confirmed)
        else:
            encrypt_root(args)
    except (HardeningError, OSError, KeyError, ValueError) as error:
        print(f"Hardening refused or interrupted: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Interrupted. Do not reboot a partially migrated system; use the recovery procedure.", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
