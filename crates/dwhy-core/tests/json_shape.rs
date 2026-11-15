//! Snapshot of the `diskwhy/v1` JSON shape. A change to these snapshots is a
//! change to the public contract: additive changes are fine within v1,
//! anything else needs `diskwhy/v2`.

use dwhy_core::report::*;

fn sample() -> ScanReport {
    let totals = Totals {
        allocated: 195_234_332_672,
        apparent: 181_397_695_055,
        files: 4_115_794,
        dirs: 298_007,
        symlinks: 40_620,
        other: 49,
        hardlinks_deduped: 197_465,
        hardlink_bytes_deduped: 12_216_655_872,
    };
    ScanReport {
        schema: SCHEMA.into(),
        tool: Tool {
            name: "diskwhy".into(),
            version: "0.0.1".into(),
        },
        host: "pc-ubuntu".into(),
        uid: 1000,
        root: false,
        generated_at: "2026-11-15T06:00:00Z".into(),
        scan: ScanSummary {
            roots: vec![RootReport {
                path: "/".into(),
                mount: "/".into(),
                totals,
            }],
            one_filesystem: true,
            elapsed_ms: 410,
            totals,
            dirs: vec![
                DirEntry {
                    path: "/".into(),
                    depth: 0,
                    allocated: 195_234_332_672,
                    apparent: 181_397_695_055,
                    files: 4_115_794,
                },
                DirEntry {
                    path: "/home".into(),
                    depth: 1,
                    allocated: 170_597_343_232,
                    apparent: 158_523_958_653,
                    files: 3_000_000,
                },
            ],
            min_dir_bytes: 104_857_600,
            unreadable: Unreadable {
                count: 2,
                entries_unknown: 3,
                known_bytes: 4096,
                dirs: vec![
                    UnreadableDir {
                        path: "/home/hermes".into(),
                        reason: UnreadableReason::PermissionDenied,
                        entries_unknown: 0,
                        known_bytes: 4096,
                        owner_uid: Some(1003),
                    },
                    UnreadableDir {
                        path: "/srv/listed".into(),
                        reason: UnreadableReason::EntriesDenied,
                        entries_unknown: 3,
                        known_bytes: 0,
                        owner_uid: Some(0),
                    },
                ],
                truncated: false,
            },
            skipped_mounts: vec![SkippedMount {
                path: "/boot/efi".into(),
                fstype: Some("vfat".into()),
                reason: SkipReason::OtherFilesystem,
            }],
            errors: vec![],
            error_count: 0,
        },
        fs: vec![FsReport {
            mount: "/".into(),
            fstype: "ext4".into(),
            source: "/dev/nvme1n1p3".into(),
            size: 420_496_252_928,
            used: 233_488_711_680,
            avail: 165_572_820_992,
            scanned: 195_234_332_672,
            full_coverage: true,
            unaccounted: Some(38_254_379_008),
            unaccounted_large: true,
            hints: vec![
                Hint {
                    kind: HintKind::Docker,
                    path: Some("/var/lib/docker".into()),
                    detail: "Docker data root".into(),
                    unreadable_dirs: 1,
                    bytes: None,
                },
                Hint {
                    kind: HintKind::DeletedOpen,
                    path: None,
                    detail: "1 deleted file(s) still held open".into(),
                    unreadable_dirs: 0,
                    bytes: Some(1 << 20),
                },
            ],
            deleted_open: DeletedOpen {
                files: 1,
                bytes: 1 << 20,
                processes_unreadable: 584,
            },
            rerun: Some("sudo /usr/local/bin/dwhy scan /".into()),
        }],
        findings: vec![Finding {
            id: "f_7c1e".into(),
            detector: "docker-volume".into(),
            probe: Some("postgres-wal".into()),
            path: "docker://volume/example_postgres_data".into(),
            bytes: 33_041_965_056,
            growth: Some(Growth {
                bytes_per_day: 4_939_212_390,
                since: "2026-11-07T07:25:00Z".into(),
            }),
            tier: Tier::Review,
            reason: "pg_wal holds 29G vs 53M data".into(),
            guards: vec![GuardResult {
                name: "container-mount".into(),
                status: GuardStatus::Warn,
                detail: "mounted by example-postgres-1 (running)".into(),
            }],
            action: Action {
                kind: ActionKind::Advice,
                text: "restore the archive target".into(),
                argv: None,
            },
            recovery: Recovery {
                cost: "n/a".into(),
                how: None,
            },
        }],
    }
}

#[test]
fn scan_report_shape() {
    insta::assert_json_snapshot!(sample());
}

#[test]
fn scan_report_round_trips() {
    let r = sample();
    let s = serde_json::to_string(&r).unwrap();
    let back: ScanReport = serde_json::from_str(&s).unwrap();
    assert_eq!(back, r);
    assert!(check_schema(&back.schema).is_ok());
    assert!(check_schema("diskwhy/v2").is_err());
}

#[test]
fn command_action_shape() {
    let a = Action {
        kind: ActionKind::Command,
        text: "cargo clean".into(),
        argv: Some(vec!["cargo".into(), "clean".into()]),
    };
    insta::assert_json_snapshot!(a, @r#"
    {
      "kind": "command",
      "text": "cargo clean",
      "argv": [
        "cargo",
        "clean"
      ]
    }
    "#);
}
