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
            dirs_omitted: None,
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
            file_identity: None,
            id: "f_7c1e".into(),
            detector: "docker-volume".into(),
            probe: Some("postgres-wal".into()),
            evidence: None,
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
        snapshot: Some(SavedSnapshot {
            id: "20261115T060000Z-1f2e3d4c".into(),
            path: "/home/u/.local/state/diskwhy/snapshots/20261115T060000Z-1f2e3d4c.json.gz".into(),
            pruned: 1,
        }),
        findings_summary: None,
    }
}

#[test]
fn scan_report_shape() {
    insta::assert_json_snapshot!(sample());
}

fn summary_finding(
    id: &str,
    path: &str,
    bytes: u64,
    nested: Option<u64>,
    tier: Tier,
    kind: ActionKind,
) -> Finding {
    Finding {
        file_identity: None,
        id: id.into(),
        detector: "cargo-target".into(),
        probe: None,
        evidence: None,
        path: path.into(),
        bytes,
        nested_bytes: nested,
        last_modified: None,
        growth: None,
        tier,
        reason: "build output".into(),
        guards: vec![],
        action: Action {
            kind,
            text: "cargo clean".into(),
            argv: None,
        },
        recovery: Recovery {
            cost: "rebuild".into(),
            how: None,
        },
    }
}

#[test]
fn scan_report_summary_shape() {
    let mut r = sample();
    r.snapshot = None;
    for (path, depth, allocated) in [
        ("/var", 1, 20_000_000_000),
        ("/home/u", 2, 160_000_000_000),
        ("/home/u/.cache", 3, 40_000_000_000),
        ("/home/u/.cache/deep", 4, 30_000_000_000),
    ] {
        r.scan.dirs.push(DirEntry {
            path: path.into(),
            depth,
            allocated,
            apparent: allocated,
            files: 10,
        });
    }
    r.scan
        .dirs
        .sort_by(|a, b| b.allocated.cmp(&a.allocated).then(a.path.cmp(&b.path)));
    r.findings.extend([
        summary_finding(
            "f_a",
            "/home/u/src/a/target",
            10_000_000_000,
            Some(2_000_000_000),
            Tier::Rebuildable,
            ActionKind::Command,
        ),
        summary_finding(
            "f_b",
            "/home/u/.cache/pip",
            3_000_000_000,
            None,
            Tier::Regenerable,
            ActionKind::RemovePath,
        ),
        summary_finding(
            "f_c",
            "/home/u/src/a/target/debug/incremental",
            2_000_000_000,
            None,
            Tier::Regenerable,
            ActionKind::RemovePath,
        ),
        summary_finding(
            "f_d",
            "/home/u/.local/share/Trash",
            1_000_000_000,
            None,
            Tier::Blocked,
            ActionKind::RemovePath,
        ),
    ]);
    r.summarize(
        None,
        SummaryLimits {
            max_findings: 2,
            max_dirs: 4,
            max_depth: 3,
        },
    );
    insta::assert_json_snapshot!(r);
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
        file_identity: None,
        id: id.into(),
        detector: detector.into(),
        probe: None,
        evidence: None,
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
            free_target: None,
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
                scan_root_dev: None,
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
                scan_root_dev: None,
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
        goal: None,
    }
}

#[test]
fn plan_shape() {
    insta::assert_json_snapshot!(plan_sample());
}

#[test]
fn plan_goal_shape() {
    // `dwhy plan --tier rebuildable --free 30G`: the items fall short, and
    // review findings above the ceiling are reported.
    let mut plan = plan_sample();
    plan.items.truncate(1);
    plan.bytes = plan.items[0].finding.bytes;
    plan.selection.free_target = Some(30 << 30);
    plan.goal = Some(PlanGoal {
        target_bytes: 30 << 30,
        planned_bytes: plan.bytes,
        met: false,
        shortfall_bytes: (30 << 30) - plan.bytes,
        higher_tiers: vec![HigherTierAvailable {
            tier: Tier::Review,
            count: 2,
            bytes: 12_884_901_888,
        }],
    });
    insta::assert_json_snapshot!(plan);
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
                "a review item needs the user's approval",
            ),
            apply_item(ApplyOutcome::WouldRemove, "ready"),
        ],
        freed: 9_663_676_416,
        would_free: None,
        audit_log: Some("/home/me/.local/state/diskwhy/audit.jsonl".into()),
    };
    insta::assert_json_snapshot!(r);
    let back: ApplyReport = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
    assert_eq!(back, r);
}

#[test]
fn apply_report_dry_run_shape() {
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
        dry_run: true,
        max_tier: Tier::Regenerable,
        confirm: vec![],
        items: vec![
            apply_item(ApplyOutcome::WouldRemove, "ready"),
            apply_item(
                ApplyOutcome::Refused,
                "a review item needs the user's approval",
            ),
        ],
        freed: 0,
        would_free: Some(9_663_676_416),
        audit_log: None,
    };
    insta::assert_json_snapshot!(r);
    let back: ApplyReport = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
    assert_eq!(back, r);
}

#[test]
fn apply_report_without_would_free_or_audit_log_still_parses() {
    let mut v = serde_json::to_value(ApplyReport {
        schema: SCHEMA.into(),
        tool: Tool::current(),
        host: "h".into(),
        uid: 1000,
        generated_at: "2026-11-16T04:10:00Z".into(),
        plan_created_at: "2026-11-16T04:00:00Z".into(),
        dry_run: true,
        max_tier: Tier::Regenerable,
        confirm: vec![],
        items: vec![],
        freed: 0,
        would_free: Some(1),
        audit_log: Some("/a".into()),
    })
    .unwrap();
    let obj = v.as_object_mut().unwrap();
    obj.remove("would_free");
    obj.remove("audit_log");
    let back: ApplyReport = serde_json::from_value(v).unwrap();
    assert_eq!((back.would_free, back.audit_log), (None, None));
}

#[test]
fn error_report_shape() {
    let tool = Tool {
        name: "diskwhy".into(),
        version: "0.0.1".into(),
    };
    let reports = [
        ErrorReport {
            tool: tool.clone(),
            ..ErrorReport::new(
                ErrorKind::Usage,
                "unexpected argument '--no-such-flag' found",
                Some("to pass '--no-such-flag' as a value, use '-- --no-such-flag'".into()),
                1,
            )
        },
        ErrorReport {
            tool: tool.clone(),
            ..ErrorReport::new(
                ErrorKind::Error,
                "/definitely/not/here: No such file or directory (os error 2)",
                None,
                1,
            )
        },
        ErrorReport {
            tool,
            ..ErrorReport::new(
                ErrorKind::Refused,
                "no terminal to confirm on",
                Some("pass --yes to remove without asking, or --dry-run to preview".into()),
                3,
            )
        },
    ];
    insta::assert_json_snapshot!(reports);
    for r in reports {
        assert_eq!(r.schema, SCHEMA);
        let back: ErrorReport = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(back, r);
    }
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
        max_tier: None,
        confirm: None,
        yes: None,
        tty: None,
    };
    let end = AuditRecord {
        event: AuditEvent::End,
        outcome: Some(ApplyOutcome::Removed),
        detail: Some("ran cargo clean".into()),
        ..start.clone()
    };
    // A record that says how apply was invoked (diskwhy records it now;
    // the two above are what older versions wrote, and still parse).
    let invoked = AuditRecord {
        max_tier: Some(Tier::Rebuildable),
        confirm: Some(vec!["f_0123456789ab".into()]),
        yes: Some(true),
        tty: Some(false),
        ..end.clone()
    };
    let records = vec![start, end, invoked];
    insta::assert_json_snapshot!(records);
    for r in &records {
        let line = serde_json::to_string(r).unwrap();
        assert_eq!(&serde_json::from_str::<AuditRecord>(&line).unwrap(), r);
    }
}

#[test]
fn audit_report_shape() {
    let record = AuditRecord {
        schema: SCHEMA.into(),
        time: "2026-11-16T04:10:01Z".into(),
        host: "pc-ubuntu".into(),
        uid: 1000,
        pid: 4242,
        event: AuditEvent::End,
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
        outcome: Some(ApplyOutcome::Removed),
        detail: Some("ran cargo clean".into()),
        max_tier: Some(Tier::Rebuildable),
        confirm: Some(Vec::new()),
        yes: Some(true),
        tty: Some(false),
    };
    let report = AuditReport {
        schema: SCHEMA.into(),
        tool: Tool {
            name: "diskwhy".into(),
            version: "0.0.1".into(),
        },
        host: "pc-ubuntu".into(),
        uid: 1000,
        path: "/home/me/.local/state/diskwhy/audit.jsonl".into(),
        missing: false,
        total: 3,
        omitted: 2,
        malformed_lines: 1,
        records: vec![record],
    };
    let missing = AuditReport {
        path: "/home/new/.local/state/diskwhy/audit.jsonl".into(),
        missing: true,
        total: 0,
        omitted: 0,
        malformed_lines: 0,
        records: Vec::new(),
        ..report.clone()
    };
    insta::assert_json_snapshot!(vec![report.clone(), missing.clone()]);
    for r in [report, missing] {
        let back: AuditReport = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(back, r);
    }
}

#[test]
fn snapshot_shape() {
    let totals = Totals {
        allocated: 79_456_894_976,
        apparent: 75_000_000_000,
        files: 2_000_000,
        dirs: 150_000,
        symlinks: 20_000,
        other: 3,
        hardlinks_deduped: 1_000,
        hardlink_bytes_deduped: 2_000_000,
    };
    let usage_line = |count, active, bytes| UsageLine {
        count,
        active,
        bytes,
    };
    insta::assert_json_snapshot!(Snapshot {
        schema: SCHEMA.into(),
        tool: Tool {
            name: "diskwhy".into(),
            version: "0.0.1".into(),
        },
        host: "pc-ubuntu".into(),
        uid: 1000,
        created_at: "2026-11-16T06:00:00Z".into(),
        scan: SnapshotScan {
            roots: vec!["/home/u".into()],
            one_filesystem: true,
            min_dir_bytes: 104_857_600,
            totals,
            detectors: vec!["cargo-target".into(), "docker-volume".into()],
            skipped_mounts: vec!["/home/u/mnt".into()],
        },
        dirs: vec![SnapshotDir {
            path: "/home/u".into(),
            allocated: 79_456_894_976,
            apparent: 75_000_000_000,
            files: 2_000_000,
        }],
        fs: vec![SnapshotFs {
            mount: "/".into(),
            fstype: "ext4".into(),
            size: 420_906_795_008,
            used: 360_777_252_864,
            avail: 38_712_254_464,
            scanned: 79_456_894_976,
        }],
        docker: Some(SnapshotDocker {
            usage: DockerUsage {
                root_dir: "/var/lib/docker".into(),
                containerd_image_store: true,
                images: usage_line(2, 1, 1_000_000_000),
                containers: usage_line(1, 1, 4096),
                volumes: usage_line(1, 1, 33_041_965_056),
                build_cache: usage_line(3, 0, 500_000_000),
                total: 34_541_969_152,
            },
            images: vec![SnapshotImage {
                id: "sha256:6d03d5821c0d".into(),
                tags: vec!["postgres:16-alpine".into()],
                bytes: 440_401_920,
            }],
            containers: vec![SnapshotContainer {
                id: "c0ffee".into(),
                name: "example-postgres-1".into(),
                image: "postgres:16-alpine".into(),
                state: "running".into(),
                bytes: Some(4096),
            }],
            volumes: vec![
                SnapshotVolume {
                    name: "example_postgres_data".into(),
                    bytes: Some(33_041_965_056),
                    created_at: Some("2026-11-01T10:00:00Z".into()),
                },
                SnapshotVolume {
                    name: "unsized".into(),
                    bytes: None,
                    created_at: None,
                },
            ],
        }),
        findings: vec![SnapshotFinding {
            id: "f_7c1e00000000".into(),
            detector: "docker-volume".into(),
            path: "docker://volume/example_postgres_data".into(),
            bytes: 33_041_965_056,
            tier: Tier::Review,
        }],
    });
}

#[test]
fn diff_report_shape() {
    let change = |kind, name: &str, before: Option<u64>, after: Option<u64>| {
        let c = after.unwrap_or(0) as i64 - before.unwrap_or(0) as i64;
        Change {
            kind,
            name: name.into(),
            id: None,
            detector: None,
            before,
            after,
            change: c,
            at_least: false,
            bytes_per_day: c / 2,
        }
    };
    let mut new_dir = change(ChangeKind::Dir, "/home/u/new", None, Some(262_144_000));
    new_dir.change = 157_286_400;
    new_dir.bytes_per_day = 78_643_200;
    new_dir.at_least = true;
    let mut image = change(
        ChangeKind::Image,
        "postgres:16-alpine",
        None,
        Some(440_401_920),
    );
    image.id = Some("sha256:6d03d5821c0d".into());
    let mut finding = change(
        ChangeKind::Finding,
        "docker://volume/example_postgres_data",
        Some(23_163_179_008),
        Some(33_041_965_056),
    );
    finding.id = Some("f_7c1e".into());
    finding.detector = Some("docker-volume".into());
    insta::assert_json_snapshot!(DiffReport {
        schema: SCHEMA.into(),
        tool: Tool {
            name: "diskwhy".into(),
            version: "0.0.1".into(),
        },
        host: "pc-ubuntu".into(),
        uid: 1000,
        generated_at: "2026-11-16T06:00:00Z".into(),
        since: DiffBase {
            id: Some("20261114T060000Z-0123abcd".into()),
            path: "/home/u/.local/state/diskwhy/snapshots/20261114T060000Z-0123abcd.json.gz".into(),
            created_at: "2026-11-14T06:00:00Z".into(),
            roots: vec!["/home/u".into()],
            one_filesystem: true,
            min_dir_bytes: 104_857_600,
        },
        roots: vec!["/home/u".into()],
        one_filesystem: true,
        elapsed_secs: 172_800,
        min_change: 10_485_760,
        fs: vec![change(
            ChangeKind::Fs,
            "/",
            Some(350_000_000_000),
            Some(360_777_252_864)
        )],
        dirs: vec![
            new_dir,
            change(ChangeKind::Dir, "/home/u/gone", Some(209_715_200), None),
        ],
        docker_compared: true,
        docker: vec![
            change(
                ChangeKind::Volume,
                "example_postgres_data",
                Some(23_163_179_008),
                Some(33_041_965_056)
            ),
            image,
            change(
                ChangeKind::BuildCache,
                "build cache",
                Some(500_000_000),
                Some(0)
            ),
        ],
        findings: vec![finding],
        notes: vec!["findings not compared (detector ran on one side only): go-build".into()],
        snapshot: Some(SavedSnapshot {
            id: "20261116T060000Z-0123abcd".into(),
            path: "/home/u/.local/state/diskwhy/snapshots/20261116T060000Z-0123abcd.json.gz".into(),
            pruned: 0,
        }),
    });
}

#[test]
fn watch_report_shape() {
    let rate = |kind, name: &str, before: Option<u64>, after: Option<u64>| {
        let c = after.unwrap_or(0) as i64 - before.unwrap_or(0) as i64;
        Rate {
            kind,
            name: name.into(),
            id: None,
            before,
            after,
            change: c,
            bytes_per_minute: c,
        }
    };
    let mut container = rate(
        ChangeKind::Container,
        "example-db-1",
        Some(4_096),
        Some(8_192),
    );
    container.id = Some("c1d2e3f4a5b6".into());
    insta::assert_json_snapshot!(WatchReport {
        schema: SCHEMA.into(),
        tool: Tool {
            name: "diskwhy".into(),
            version: "0.0.1".into(),
        },
        host: "pc-ubuntu".into(),
        uid: 1000,
        started_at: "2026-11-18T02:00:00Z".into(),
        generated_at: "2026-11-18T02:01:01Z".into(),
        roots: vec!["/home/u".into()],
        one_filesystem: true,
        for_secs: 60,
        elapsed_ms: 60_000,
        min_change: 1_048_576,
        fs: vec![rate(
            ChangeKind::Fs,
            "/",
            Some(350_000_000_000),
            Some(350_100_663_296)
        )],
        dirs: vec![
            rate(
                ChangeKind::Dir,
                "/home/u/pg/pg_wal",
                Some(838_860_800),
                Some(939_524_096)
            ),
            rate(ChangeKind::Dir, "/home/u/tmp/new", None, Some(2_097_152)),
            rate(ChangeKind::Dir, "/home/u/tmp/gone", Some(3_145_728), None),
        ],
        docker_compared: true,
        docker: vec![
            rate(
                ChangeKind::Volume,
                "example_pg_wal",
                Some(1_073_741_824),
                Some(1_174_405_120)
            ),
            container,
        ],
        notes: vec![],
    });
}

fn probed_finding() -> Finding {
    Finding {
        file_identity: None,
        id: "f_7c1e00000000".into(),
        detector: "docker-volume".into(),
        probe: Some("postgres-wal".into()),
        path: "docker://volume/example_postgres_data".into(),
        bytes: 33_041_965_056,
        nested_bytes: None,
        last_modified: Some("2026-11-13T02:10:00Z".into()),
        growth: None,
        tier: Tier::Review,
        reason: "pg_wal holds 29G vs 53M data; archiving is failing, with 151 failures in total (last failure 2026-11-13T02:10:00Z, last success 2026-11-07T07:25:00Z) \
                 (target s3test exited); volume example_postgres_data holds 30.8G and is mounted \
                 by example-postgres-1 (running)"
            .into(),
        guards: vec![GuardResult {
            name: "container-mount".into(),
            status: GuardStatus::Warn,
            detail: "mounted by example-postgres-1 (running)".into(),
        }],
        action: Action {
            kind: ActionKind::Advice,
            text: "restore the archive target s3test; WAL is freed at the next checkpoint".into(),
            argv: None,
        },
        recovery: Recovery {
            cost: "n/a: nothing is removed; Postgres recycles WAL itself".into(),
            how: None,
        },
        evidence: Some(Evidence {
            postgres_wal: Some(PostgresWal {
                container: "example-postgres-1".into(),
                wal_bytes: Some(31_138_512_896),
                data_bytes: Some(55_574_528),
                failed_count: Some(151),
                last_archived_at: Some("2026-11-07T07:25:00Z".into()),
                last_failed_at: Some("2026-11-13T02:10:00Z".into()),
                last_failed_wal: Some("000000010000000000000097".into()),
                archive_mode: Some("on".into()),
                archive_program: Some("aws".into()),
                archive_timeout: Some("10s".into()),
                targets: vec![
                    ArchiveTarget {
                        host: "s3test".into(),
                        container: Some("example-s3test-1".into()),
                        state: "exited".into(),
                    },
                ],
                unmatched_hosts: 2,
                source: EvidenceSource::Psql,
                notes: vec![],
                archive_library: None,
                ready_wal_files: None,
                wal_on_other_mount: false,
                historical_command: false,
            }),
        }),
    }
}

#[test]
fn postgres_wal_evidence_shape() {
    let f = probed_finding();
    insta::assert_json_snapshot!(f);
    let back: Finding = serde_json::from_str(&serde_json::to_string(&f).unwrap()).unwrap();
    assert_eq!(back, f);

    let mut without_count = serde_json::to_value(&f).unwrap();
    without_count["evidence"]["postgres_wal"]
        .as_object_mut()
        .unwrap()
        .remove("unmatched_hosts");
    let back: Finding = serde_json::from_value(without_count.clone()).unwrap();
    assert_eq!(
        back.evidence
            .as_ref()
            .unwrap()
            .postgres_wal
            .as_ref()
            .unwrap()
            .unmatched_hosts,
        0
    );
    assert_eq!(serde_json::to_value(&back).unwrap(), without_count);
}

#[test]
fn api_only_evidence_shape() {
    let mut ev = probed_finding().evidence.unwrap().postgres_wal.unwrap();
    ev.wal_bytes = None;
    ev.data_bytes = None;
    ev.last_archived_at = None;
    ev.source = EvidenceSource::ApiOnly;
    ev.notes = vec!["psql not used: psql failed".into()];
    insta::assert_json_snapshot!(ev);
}

#[test]
fn optional_postgres_wal_fields_are_additive() {
    let ev = probed_finding().evidence.unwrap().postgres_wal.unwrap();
    let old = serde_json::to_value(&ev).unwrap();
    // Unset, the newer fields are absent: v1 readers see the same shape.
    for key in [
        "archive_library",
        "ready_wal_files",
        "wal_on_other_mount",
        "historical_command",
    ] {
        assert!(old.get(key).is_none(), "{key}");
    }
    // A report written before them still reads, with them unset.
    let back: PostgresWal = serde_json::from_value(old).unwrap();
    assert_eq!(back, ev);

    let mut set = ev.clone();
    set.archive_library = Some("basic_archive".into());
    set.ready_wal_files = Some(481);
    set.wal_on_other_mount = true;
    set.historical_command = true;
    let json = serde_json::to_value(&set).unwrap();
    assert_eq!(json["archive_library"], "basic_archive");
    assert_eq!(json["ready_wal_files"], 481);
    assert_eq!(json["wal_on_other_mount"], true);
    assert_eq!(json["historical_command"], true);
    assert_eq!(serde_json::from_value::<PostgresWal>(json).unwrap(), set);
}

#[test]
fn findings_without_evidence_have_no_evidence_key() {
    let mut f = probed_finding();
    f.evidence = None;
    let v = serde_json::to_value(&f).unwrap();
    assert!(v.get("evidence").is_none());
    let back: Finding = serde_json::from_value(v).unwrap();
    assert_eq!(back.evidence, None);
}

#[test]
fn explain_report_shape() {
    let tool = Tool {
        name: "diskwhy".into(),
        version: "0.0.1".into(),
    };
    // An id resolved through a snapshot to a probed Docker volume.
    let mut probed = probed_finding();
    probed.growth = Some(Growth {
        bytes_per_day: 4_831_838_208,
        since: "2026-11-12T06:00:00Z".into(),
    });
    let by_id = ExplainReport {
        schema: SCHEMA.into(),
        tool: tool.clone(),
        host: "pc-ubuntu".into(),
        uid: 1000,
        generated_at: "2026-11-13T06:00:00Z".into(),
        query: "f_7c1e00000000".into(),
        resolved: ExplainResolved {
            via: ExplainVia::Id,
            snapshot: Some(ExplainSnapshot {
                id: "20261112T060000Z-0123abcd".into(),
                path: "/home/me/.local/state/diskwhy/snapshots/20261112T060000Z-0123abcd.json.gz"
                    .into(),
                created_at: "2026-11-12T06:00:00Z".into(),
            }),
        },
        path: "docker://volume/example_postgres_data".into(),
        finding: Some(probed),
        gone: false,
        size: None,
        inside: vec![],
        notes: vec![],
    };
    // A path no detector claims, with a finding inside it.
    let by_path = ExplainReport {
        query: "app".into(),
        resolved: ExplainResolved {
            via: ExplainVia::Path,
            snapshot: None,
        },
        path: "/home/me/app".into(),
        finding: None,
        size: Some(ExplainSize {
            allocated: 9_700_000_000,
            apparent: 9_500_000_000,
        }),
        inside: vec![FindingRef {
            id: "f_c2b7afdaa165".into(),
            path: "/home/me/app/target".into(),
            detector: "cargo-target".into(),
            bytes: 9_663_676_416,
            tier: Tier::Rebuildable,
        }],
        notes: vec!["not run: git-worktree (see `dwhy doctor`)".into()],
        ..by_id.clone()
    };
    let reports = vec![by_id, by_path];
    insta::assert_json_snapshot!(reports);
    for r in &reports {
        let back: ExplainReport = serde_json::from_str(&serde_json::to_string(r).unwrap()).unwrap();
        assert_eq!(&back, r);
    }
    // Optional parts may be missing when read back.
    let mut v = serde_json::to_value(&reports[0]).unwrap();
    for k in ["finding", "gone", "inside", "notes"] {
        v.as_object_mut().unwrap().remove(k);
    }
    let back: ExplainReport = serde_json::from_value(v).unwrap();
    assert!(back.finding.is_none() && !back.gone && back.inside.is_empty());
}

fn doctor_sample() -> DoctorReport {
    DoctorReport {
        schema: SCHEMA.into(),
        tool: Tool {
            name: "diskwhy".into(),
            version: "0.1.0".into(),
        },
        host: "devbox".into(),
        uid: 1000,
        euid: 1000,
        root: false,
        docker_group: true,
        docker_socket: DockerSocket {
            path: "/var/run/docker.sock".into(),
            exists: true,
            accessible: true,
        },
        tools: vec![
            ToolStatus {
                name: "docker".into(),
                path: Some("/usr/bin/docker".into()),
                off_path: None,
                enables: vec!["docker-volume".into(), "postgres-wal".into()],
            },
            ToolStatus {
                name: "cargo".into(),
                path: None,
                off_path: Some("/home/u/.cargo/bin/cargo".into()),
                enables: vec!["cargo-target".into()],
            },
        ],
        detectors: vec![DetectorStatus {
            name: "docker-volume".into(),
            milestone: "M1".into(),
            status: DetectorAvailability::Available,
            detail: "Docker socket accessible".into(),
        }],
        probes: vec![DetectorStatus {
            name: "postgres-wal".into(),
            milestone: "M3".into(),
            status: DetectorAvailability::Available,
            detail: "uses docker-volume findings, the Engine API and read-only psql through `docker exec`"
                .into(),
        }],
        notes: vec!["member of the docker group (root-equivalent)".into()],
    }
}

#[test]
fn doctor_report_shape() {
    insta::assert_json_snapshot!(doctor_sample());
}

#[test]
fn doctor_report_round_trips() {
    let r = doctor_sample();
    let back: DoctorReport = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
    assert_eq!(back, r);
}

#[test]
fn doctor_report_without_probes_reads_back_with_no_probes() {
    let mut v = serde_json::to_value(doctor_sample()).unwrap();
    v.as_object_mut().unwrap().remove("probes").unwrap();
    let back: DoctorReport = serde_json::from_value(v).unwrap();
    assert!(back.probes.is_empty());
    let mut expected = doctor_sample();
    expected.probes.clear();
    assert_eq!(back, expected);
}
