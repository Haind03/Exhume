//! Parallel directory walk on the worker pool: each directory's subdirectories are fanned out as
//! separate tasks, so deep trees (/usr, web roots, home directories) are listed by every thread
//! at once. lstat only; symlinks are never followed.

use std::fs::{self, Metadata};
use std::sync::atomic::{AtomicUsize, Ordering};

use rayon::prelude::*;

pub struct Walk<'a, T> {
    pub max_depth: u32,
    /// Stop collecting once this many items were produced (bounds work on huge trees).
    pub limit: usize,
    /// Directories not to enter (exact path).
    pub skip_dir: &'a (dyn Fn(&str, &str) -> bool + Sync),
    /// Called for every regular file; returns an item to collect.
    pub visit: &'a (dyn Fn(&str, &Metadata) -> Option<T> + Sync),
}

/// Walk `roots` in parallel. Returns the collected items and the number of regular files seen.
pub fn par_walk<T: Send>(roots: &[String], w: &Walk<T>) -> (Vec<T>, usize) {
    let seen = AtomicUsize::new(0);
    let made = AtomicUsize::new(0);
    let items = roots
        .par_iter()
        .flat_map_iter(|r| walk_dir(r, 0, w, &seen, &made))
        .collect();
    (items, seen.into_inner())
}

fn walk_dir<T: Send>(
    dir: &str,
    depth: u32,
    w: &Walk<T>,
    seen: &AtomicUsize,
    made: &AtomicUsize,
) -> Vec<T> {
    if depth > w.max_depth || made.load(Ordering::Relaxed) >= w.limit {
        return Vec::new();
    }
    let Ok(rd) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut subdirs = Vec::new();
    for e in rd.flatten() {
        let path = e.path().to_string_lossy().into_owned();
        let Ok(m) = fs::symlink_metadata(&path) else {
            continue;
        };
        if m.is_dir() {
            let name = e.file_name().to_string_lossy().into_owned();
            if !(w.skip_dir)(&path, &name) {
                subdirs.push(path);
            }
        } else if m.is_file() {
            seen.fetch_add(1, Ordering::Relaxed);
            if let Some(t) = (w.visit)(&path, &m) {
                made.fetch_add(1, Ordering::Relaxed);
                out.push(t);
            }
        }
    }
    if subdirs.len() == 1 {
        out.extend(walk_dir(&subdirs[0], depth + 1, w, seen, made));
    } else if !subdirs.is_empty() {
        let nested: Vec<Vec<T>> = subdirs
            .par_iter()
            .map(|d| walk_dir(d, depth + 1, w, seen, made))
            .collect();
        out.extend(nested.into_iter().flatten());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walks_tree_in_parallel_without_following_symlinks() {
        let base = std::env::temp_dir().join(format!("exhume-walk-{}", std::process::id()));
        let b = base.to_str().unwrap().to_string();
        for d in ["a/b/c", "a/skipme/x", "d"] {
            fs::create_dir_all(format!("{b}/{d}")).unwrap();
        }
        for f in [
            "a/1.php",
            "a/b/2.php",
            "a/b/c/3.txt",
            "a/skipme/x/4.php",
            "d/5.php",
        ] {
            fs::write(format!("{b}/{f}"), "x").unwrap();
        }
        std::os::unix::fs::symlink("/usr", format!("{b}/d/link")).unwrap();
        let w = Walk {
            max_depth: 10,
            limit: usize::MAX,
            skip_dir: &|_, n| n == "skipme",
            visit: &|p, _| p.ends_with(".php").then(|| p.to_string()),
        };
        let (mut got, seen) = par_walk(std::slice::from_ref(&b), &w);
        got.sort();
        assert_eq!(
            got,
            vec![
                format!("{b}/a/1.php"),
                format!("{b}/a/b/2.php"),
                format!("{b}/d/5.php")
            ]
        );
        assert_eq!(seen, 4, "skipped dir and symlink target are not visited");
        let limited = Walk { limit: 1, ..w };
        assert!(par_walk(std::slice::from_ref(&b), &limited).0.len() <= 3);
        fs::remove_dir_all(&base).unwrap();
    }
}
