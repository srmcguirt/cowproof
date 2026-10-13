//! Removing a directory tree the way cowproof needs it: a tree that holds a read-only
//! directory (mode 0555, which a byte copy of a compile-cache seed keeps) can still be removed,
//! and no symlink is ever followed.

use std::fs;
use std::io;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// Remove `path` whatever it is, for a seed, a copy of one, or a stale work directory.
///
/// * A file or a symlink is unlinked (a symlink is never followed, so what it points at is
///   untouched). A path that is already gone is `Ok`.
/// * A directory is walked with `symlink_metadata`-style typing (`DirEntry::file_type` does not
///   follow links). Before its children are removed it is made owner-writable (`u+rwx`), so a
///   directory a copy left at 0555 does not stop `remove_dir_all`'s EACCES on its children.
///   The mode change is made on a descriptor opened with `O_NOFOLLOW | O_DIRECTORY`, so a
///   directory swapped for a symlink between the listing and the change fails to open (an
///   error) and nothing is changed through the link.
///
/// A directory the owner cannot read at all (no `u+r`) cannot be opened that way and is
/// reported as the permission error; it is not changed by path, because a path can be swapped
/// for a symlink and `chmod(2)` follows it.
pub fn remove_tree(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => remove_dir(path),
        Ok(_) => fs::remove_file(path),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn remove_dir(dir: &Path) -> io::Result<()> {
    make_owner_writable(dir)?;
    for item in fs::read_dir(dir)? {
        let item = item?;
        let path = item.path();
        if item.file_type()?.is_dir() {
            remove_dir(&path)?;
        } else {
            fs::remove_file(&path)?;
        }
    }
    fs::remove_dir(dir)
}

/// `u+rwx` on the directory `dir` itself, never through a symlink.
fn make_owner_writable(dir: &Path) -> io::Result<()> {
    let handle = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(dir)?;
    let mode = handle.metadata()?.permissions().mode();
    if mode & 0o700 != 0o700 {
        handle.set_permissions(fs::Permissions::from_mode(mode | 0o700))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn tmp() -> TempDir {
        tempfile::Builder::new()
            .prefix("cp-fsutil-")
            .tempdir_in("/var/tmp")
            .unwrap()
    }

    fn mode(p: &Path) -> u32 {
        fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn a_tree_with_read_only_directories_is_removed() {
        let t = tmp();
        let root = t.path().join("seed");
        fs::create_dir_all(root.join("ro/inner/deeper")).unwrap();
        fs::write(root.join("ro/inner/data"), "x").unwrap();
        fs::write(root.join("ro/inner/deeper/data"), "y").unwrap();
        fs::set_permissions(
            root.join("ro/inner/deeper"),
            fs::Permissions::from_mode(0o555),
        )
        .unwrap();
        fs::set_permissions(root.join("ro/inner"), fs::Permissions::from_mode(0o555)).unwrap();
        fs::set_permissions(root.join("ro"), fs::Permissions::from_mode(0o555)).unwrap();
        let result = remove_tree(&root);
        // Leave nothing the TempDir cannot remove, whatever the assertions find.
        if root.exists() {
            fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        }
        result.unwrap();
        assert!(fs::symlink_metadata(&root).is_err());
    }

    #[test]
    fn a_symlink_is_unlinked_and_what_it_points_at_is_untouched() {
        let t = tmp();
        let outside = t.path().join("outside");
        fs::create_dir_all(outside.join("sub")).unwrap();
        fs::write(outside.join("file"), "keep").unwrap();
        fs::set_permissions(outside.join("sub"), fs::Permissions::from_mode(0o555)).unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o555)).unwrap();
        let root = t.path().join("seed");
        fs::create_dir_all(root.join("ro")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("ro/link")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("top-link")).unwrap();
        fs::set_permissions(root.join("ro"), fs::Permissions::from_mode(0o555)).unwrap();
        let result = remove_tree(&root);
        let (outside_mode, sub_mode) = (mode(&outside), mode(&outside.join("sub")));
        let kept = fs::read_to_string(outside.join("file"));
        for dir in [&outside, &outside.join("sub")] {
            fs::set_permissions(dir, fs::Permissions::from_mode(0o755)).unwrap();
        }
        result.unwrap();
        assert!(fs::symlink_metadata(&root).is_err());
        assert_eq!(outside_mode, 0o555);
        assert_eq!(sub_mode, 0o555);
        assert_eq!(kept.unwrap(), "keep");
    }

    #[test]
    fn the_mode_change_refuses_a_symlink_and_leaves_its_target_alone() {
        // The swap-race protection, without the race: `make_owner_writable` is handed a path
        // that is a symlink to a read-only directory. `O_NOFOLLOW` makes the open fail, so
        // no mode change can land on the target.
        let t = tmp();
        let outside = t.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o555)).unwrap();
        let link = t.path().join("link");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        let result = make_owner_writable(&link);
        let after = mode(&outside);
        // Restore the mode before any assertion, so the temp dir stays removable.
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(result.is_err(), "a symlink was opened as a directory");
        assert_eq!(after, 0o555, "the target's mode was changed through a link");
    }

    #[test]
    fn a_symlink_at_the_path_itself_is_unlinked_not_followed() {
        let t = tmp();
        let outside = t.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("file"), "keep").unwrap();
        let link = t.path().join("link");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        remove_tree(&link).unwrap();
        assert!(fs::symlink_metadata(&link).is_err());
        assert_eq!(fs::read_to_string(outside.join("file")).unwrap(), "keep");
    }

    #[test]
    fn a_missing_path_is_fine_and_a_file_is_removed() {
        let t = tmp();
        remove_tree(&t.path().join("nothing")).unwrap();
        let f = t.path().join("f");
        fs::write(&f, "x").unwrap();
        remove_tree(&f).unwrap();
        assert!(fs::symlink_metadata(&f).is_err());
    }
}
