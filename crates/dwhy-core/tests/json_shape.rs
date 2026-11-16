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
            nested_bytes: None,
            last_modified: Some("2026-11-13T02:10:00Z".into()),
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
        detectors: vec![
            DetectorRun {
                name: "cargo-target".into(),
                status: DetectorAvailability::Available,
                detail: "uses `cargo` for removal".into(),
                ran: true,
                findings: 6,
                elapsed_ms: 1,
                error: None,
            },
            DetectorRun {
                name: "venv".into(),
                status: DetectorAvailability::NotImplemented,
                detail: "not implemented yet (M1)".into(),
                ran: false,
                findings: 0,
                elapsed_ms: 0,
                error: None,
            },
            DetectorRun {
                name: "docker-image".into(),
                status: DetectorAvailability::Available,
                detail: "uses the docker CLI and socket".into(),
                ran: true,
                findings: 0,
                elapsed_ms: 120_000,
                error: Some("docker API /system/df: no response within 120s".into()),
            },
        ],
        docker: Some(DockerUsage {
            root_dir: "/var/lib/docker".into(),
            containerd_image_store: true,
            images: UsageLine {
                count: 30,
                active: 16,
                bytes: 22_426_296_039,
            },
            containers: UsageLine {
                count: 33,
                active: 33,
                bytes: 648_278_016,
            },
            volumes: UsageLine {
                count: 15,
                active: 15,
                bytes: 1_654_201_897,
            },
            build_cache: UsageLine {
                count: 92,
                active: 0,
                bytes: 4_616_635_167,
            },
            total: 29_345_411_119,
        }),
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

fn plan_finding(id: &str, detector: &str, path: &str, tier: Tier, action: Action) -> Finding {
    Finding {
        id: id.into(),
        detector: detector.into(),
        probe: None,
        path: path.into(),
        bytes: 9_663_676_416,
        nested_bytes: None,
        last_modified: Some("2026-11-02T10:00:00Z".into()),
        growth: None,
        tier,
        reason: "a reason".into(),
        guards: vec![GuardResult {
            name: "in-use-cwd".into(),
            status: GuardStatus::Pass,
            detail: "no process has its working directory in it".into(),
        }],
        action,
        recovery: Recovery {
            cost: "rebuild".into(),
            how: Some("cargo build".into()),
        },
    }
}

fn plan_sample() -> Plan {
    Plan {
        schema: SCHEMA.into(),
        tool: Tool {
            name: "diskwhy".into(),
            version: "0.0.1".into(),
        },
        host: "pc-ubuntu".into(),
        uid: 1000,
        created_at: "2026-11-16T04:00:00Z".into(),
        expires_at: "2026-11-16T05:00:00Z".into(),
        scan: PlanScan {
            roots: vec!["/home/me".into()],
            one_filesystem: true,
            detectors: None,
        },
        selection: PlanSelection {
            tier: Some(Tier::Rebuildable),
            select: vec![],
        },
        items: vec![
            PlanItem {
                finding: plan_finding(
                    "f_c2b7afdaa165",
                    "cargo-target",
                    "/home/me/x/target",
                    Tier::Rebuildable,
                    Action {
                        kind: ActionKind::Command,
                        text: "cargo clean --manifest-path /home/me/x/Cargo.toml --target-dir /home/me/x/target".into(),
                        argv: Some(
                            [
                                "cargo",
                                "clean",
                                "--manifest-path",
                                "/home/me/x/Cargo.toml",
                                "--target-dir",
                                "/home/me/x/target",
                            ]
                            .map(String::from)
                            .to_vec(),
                        ),
                    },
                ),
                fingerprint: Fingerprint {
                    dev: Some(66311),
                    inode: Some(3_698_100),
                    newest_mtime: Some(1_794_100_000),
                    size_bucket: 133,
                    git: None,
                    docker_id: None,
                },
            },
            PlanItem {
                finding: plan_finding(
                    "f_0a1b2c3d4e5f",
                    "docker-image",
                    "docker://image/old:latest",
                    Tier::Review,
                    Action {
                        kind: ActionKind::Command,
                        text: "docker image rm old:latest".into(),
                        argv: Some(["docker", "image", "rm", "old:latest"].map(String::from).to_vec()),
                    },
                ),
                fingerprint: Fingerprint {
                    dev: None,
                    inode: None,
                    newest_mtime: None,
                    size_bucket: 133,
                    git: None,
                    docker_id: Some("sha256:5bcecbbe34b6".into()),
                },
            },
        ],
        blocked: vec![plan_finding(
            "f_1122334455aa",
            "git-worktree",
            "/home/me/.t3/worktrees/app/wip",
            Tier::Blocked,
            Action {
                kind: ActionKind::Command,
                text: "git -C /home/me/app worktree remove /home/me/.t3/worktrees/app/wip".into(),
                argv: None,
            },
        )],
        bytes: 19_327_352_832,
    }
}

#[test]
fn plan_shape() {
    insta::assert_json_snapshot!(plan_sample());
}

#[test]
fn plan_git_fingerprint_shape() {
    let fp = Fingerprint {
        dev: Some(1),
        inode: Some(2),
        newest_mtime: Some(3),
        size_bucket: 4,
        git: Some(GitFingerprint {
            head: "89525f0cf72cb8083d8c4ae9c7a3f345e031dc7b".into(),
            status_hash: "cbf29ce484222325".into(),
        }),
        docker_id: None,
    };
    insta::assert_json_snapshot!(fp);
}

#[test]
fn plan_round_trips() {
    let p = plan_sample();
    let s = serde_json::to_string(&p).unwrap();
    let back: Plan = serde_json::from_str(&s).unwrap();
    assert_eq!(back, p);
}

fn apply_item(outcome: ApplyOutcome, detail: &str) -> ApplyItem {
    ApplyItem {
        id: "f_c2b7afdaa165".into(),
        detector: "cargo-target".into(),
        path: "/home/me/x/target".into(),
        tier: Tier::Rebuildable,
        bytes: 9_663_676_416,
        action: Action {
            kind: ActionKind::RemovePath,
            text: "remove /home/me/x/target (cargo not found)".into(),
            argv: None,
        },
        outcome,
        detail: detail.into(),
        guards: vec![GuardResult {
            name: "in-use-cwd".into(),
            status: GuardStatus::Pass,
            detail: "no process has its working directory in it".into(),
        }],
    }
}

#[test]
fn apply_report_shape() {
    let r = ApplyReport {
        schema: SCHEMA.into(),
        tool: Tool {
            name: "diskwhy".into(),
            version: "0.0.1".into(),
        },
        host: "pc-ubuntu".into(),
        uid: 1000,
        generated_at: "2026-11-16T04:10:00Z".into(),
        plan_created_at: "2026-11-16T04:00:00Z".into(),
        dry_run: false,
        max_tier: Tier::Rebuildable,
        confirm: vec!["f_1122334455aa".into()],
        items: vec![
            apply_item(
                ApplyOutcome::Removed,
                "removed 3 files and 2 directories, 9.0G",
            ),
            apply_item(
                ApplyOutcome::Failed,
                "cannot remove /home/me/x/target/f: Permission denied (os error 13)",
            ),
            apply_item(
                ApplyOutcome::Skipped,
                "changed since the plan: newest mtime",
            ),
            apply_item(
                ApplyOutcome::Refused,
                "review items need a person's --confirm f_c2b7afdaa165",
            ),
            apply_item(ApplyOutcome::WouldRemove, "ready"),
        ],
        freed: 9_663_676_416,
    };
    insta::assert_json_snapshot!(r);
    let back: ApplyReport = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
    assert_eq!(back, r);
}

#[test]
fn audit_record_shape() {
    let start = AuditRecord {
        schema: SCHEMA.into(),
        time: "2026-11-16T04:10:00.123456789Z".into(),
        host: "pc-ubuntu".into(),
        uid: 1000,
        pid: 4242,
        event: AuditEvent::Start,
        plan_created_at: "2026-11-16T04:00:00Z".into(),
        id: "f_c2b7afdaa165".into(),
        detector: "cargo-target".into(),
        path: "/home/me/x/target".into(),
        tier: Tier::Rebuildable,
        bytes: 9_663_676_416,
        action: Action {
            kind: ActionKind::Command,
            text: "cargo clean".into(),
            argv: Some(vec!["cargo".into(), "clean".into()]),
        },
        outcome: None,
        detail: None,
    };
    let end = AuditRecord {
        event: AuditEvent::End,
        outcome: Some(ApplyOutcome::Removed),
        detail: Some("ran cargo clean".into()),
        ..start.clone()
    };
    insta::assert_json_snapshot!(vec![start, end]);
}
