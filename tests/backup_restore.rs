// Author: Junnoh Lee <pluruel@gmail.com>
// Copyright (c) 2026 Junnoh Lee. All rights reserved.
//
// Exercises backup.sh / restore.sh directly (not the axum app). Needs a
// reachable `docker` CLI; the dev stack's `auth_rs_db_postgres` container
// must be up for the "happy path" backup test (start it with ./run.sh).

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn fresh_temp_dir(name: &str) -> PathBuf {
    let dir = env::temp_dir().join(format!(
        "auth_rs_backup_restore_test_{name}_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

#[test]
fn backup_script_syntax_is_valid() {
    let status = Command::new("bash")
        .arg("-n")
        .arg(repo_root().join("backup.sh"))
        .status()
        .expect("run bash -n backup.sh");
    assert!(status.success(), "backup.sh has a syntax error");
}

#[test]
fn restore_script_syntax_is_valid() {
    let status = Command::new("bash")
        .arg("-n")
        .arg(repo_root().join("restore.sh"))
        .status()
        .expect("run bash -n restore.sh");
    assert!(status.success(), "restore.sh has a syntax error");
}

#[test]
fn backup_produces_archive_with_dump_and_keys() {
    if !docker_available() {
        eprintln!("docker not available — skipping backup_produces_archive_with_dump_and_keys");
        return;
    }

    let out_dir = fresh_temp_dir("happy_path");
    let output = Command::new(repo_root().join("backup.sh"))
        .arg(&out_dir)
        .current_dir(repo_root())
        .output()
        .expect("run backup.sh");

    assert!(
        output.status.success(),
        "backup.sh failed (dev stack must be up via ./run.sh): stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let archive = std::fs::read_dir(&out_dir)
        .expect("read out dir")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| {
            p.extension().and_then(|e| e.to_str()) == Some("gz")
                && p.to_string_lossy().contains("auth_backup_")
        })
        .expect("archive produced");

    let listing = Command::new("tar")
        .arg("-tzf")
        .arg(&archive)
        .output()
        .expect("list archive");
    assert!(listing.status.success());
    let listing = String::from_utf8_lossy(&listing.stdout);

    assert!(
        listing.contains("postgres.dump.sql"),
        "archive missing postgres.dump.sql:\n{listing}"
    );
    assert!(listing.contains("keys/"), "archive missing keys/:\n{listing}");

    let _ = std::fs::remove_dir_all(&out_dir);
}

#[test]
fn backup_fails_hard_when_postgres_container_missing() {
    if !docker_available() {
        eprintln!(
            "docker not available — skipping backup_fails_hard_when_postgres_container_missing"
        );
        return;
    }

    let out_dir = fresh_temp_dir("missing_container");
    let output = Command::new(repo_root().join("backup.sh"))
        .arg(&out_dir)
        .env("POSTGRES_CONTAINER", "definitely_missing_container_xyz")
        .current_dir(repo_root())
        .output()
        .expect("run backup.sh");

    assert!(
        !output.status.success(),
        "backup.sh must fail hard when the postgres container is missing (regression test \
         for silent data-loss bug) — got exit {:?}",
        output.status.code()
    );

    // No archive should be produced.
    let produced_archive = std::fs::read_dir(&out_dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .any(|e| e.path().extension().and_then(|e| e.to_str()) == Some("gz"))
        })
        .unwrap_or(false);
    assert!(
        !produced_archive,
        "backup.sh must not produce an archive when the DB dump could not be taken"
    );

    let _ = std::fs::remove_dir_all(&out_dir);
}

#[test]
fn restore_fails_without_archive_argument() {
    let output = Command::new(repo_root().join("restore.sh"))
        .current_dir(repo_root())
        .output()
        .expect("run restore.sh");

    assert!(
        !output.status.success(),
        "restore.sh must fail when no archive argument is given"
    );
}
