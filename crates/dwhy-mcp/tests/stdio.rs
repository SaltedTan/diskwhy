//! End to end: the real `dwhy-mcp` binary over stdio JSON-RPC, with a fake
//! home, state and config, no tools on PATH and no Docker daemon.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{Value, json};

const CARGO_TAG: &str = "Signature: 8a477f597d28d172789f06886806bc55\n# This file is a cache directory tag created by cargo.\n";

/// A fake home with a 3 MiB pip cache (regenerable, 3 days old), a 4 MiB
/// cargo `target/` (rebuildable) and a 2 MiB scratch dir (review, 30 days
/// old), plus state, config and an empty PATH dir outside it.
struct Home {
    _t: tempfile::TempDir,
    base: PathBuf,
}

impl Home {
    fn new() -> Home {
        let t = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(t.path()).unwrap();
        for d in ["home", "state", "config", "bin"] {
            fs::create_dir_all(base.join(d)).unwrap();
        }
        let h = Home { _t: t, base };
        let home = h.home();
        // Different sizes, so the plan's order (largest first) is fixed.
        for (f, size) in [
            (home.join(".cache/pip/http/blob"), 3 << 20),
            (home.join("scratch/old/blob"), 2 << 20),
            (home.join("app/target/debug/app"), 4 << 20),
        ] {
            fs::create_dir_all(f.parent().unwrap()).unwrap();
            fs::write(f, vec![7u8; size]).unwrap();
        }
        fs::write(home.join("app/Cargo.toml"), "[package]\nname = \"app\"\n").unwrap();
        fs::write(home.join("app/target/CACHEDIR.TAG"), CARGO_TAG).unwrap();
        age_tree(&home.join(".cache"), 3 * 86_400);
        age_tree(&home.join("scratch"), 30 * 86_400);
        h
    }
    fn home(&self) -> PathBuf {
        self.base.join("home")
    }
    fn root(&self) -> String {
        self.home().to_str().unwrap().to_string()
    }
    fn pip(&self) -> PathBuf {
        self.home().join(".cache/pip")
    }
    fn target(&self) -> PathBuf {
        self.home().join("app/target")
    }
    fn scratch(&self) -> PathBuf {
        self.home().join("scratch")
    }
    fn audit(&self) -> PathBuf {
        self.base.join("state/diskwhy/audit.jsonl")
    }
    fn snapshots(&self) -> PathBuf {
        self.base.join("state/diskwhy/snapshots")
    }
    fn write_policy(&self, text: &str) {
        let dir = self.base.join("config/diskwhy");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("policy.toml"), text).unwrap();
    }
    /// Starts `dwhy-mcp` with `args` and only this home's environment, and
    /// initializes the session.
    fn server(&self, args: &[&str]) -> Mcp {
        let mut child = Command::new(env!("CARGO_BIN_EXE_dwhy-mcp"))
            .args(args)
            .current_dir(self.home())
            .env_clear()
            .env("HOME", self.home())
            .env("PATH", self.base.join("bin"))
            .env("XDG_STATE_HOME", self.base.join("state"))
            .env("XDG_CONFIG_HOME", self.base.join("config"))
            .env("DOCKER_HOST", "unix:///nonexistent")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("run dwhy-mcp");
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let mut mcp = Mcp {
            child,
            stdin: Some(stdin),
            stdout,
            next_id: 1,
        };
        let init = mcp.request(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "dwhy-mcp-test", "version": "0"}
            }),
        );
        assert_eq!(init["result"]["serverInfo"]["name"], "dwhy-mcp", "{init}");
        mcp.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
        mcp
    }
}

/// Sets the mtime of everything under `p` (and `p`) to `secs` ago.
fn age_tree(p: &Path, secs: u64) {
    let t = std::time::SystemTime::now() - std::time::Duration::from_secs(secs);
    let mut all = Vec::new();
    let mut stack = vec![p.to_path_buf()];
    while let Some(d) = stack.pop() {
        if d.is_dir() {
            for e in fs::read_dir(&d).unwrap() {
                stack.push(e.unwrap().path());
            }
        }
        all.push(d);
    }
    for f in all.iter().rev() {
        fs::File::open(f).unwrap().set_modified(t).unwrap();
    }
}

/// A client session with a running server.
struct Mcp {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

/// What a tool call returned: `isError` and each text block as JSON.
struct Called {
    is_error: bool,
    blocks: Vec<Value>,
}

impl Called {
    fn ok(&self) -> &Value {
        assert!(!self.is_error, "{:?}", self.blocks);
        &self.blocks[0]
    }
    fn err(&self) -> &Value {
        assert!(self.is_error, "{:?}", self.blocks);
        assert_eq!(self.blocks.len(), 1, "{:?}", self.blocks);
        let e = &self.blocks[0];
        assert_eq!(e["schema"], "diskwhy/v1", "{e}");
        e
    }
}

impl Mcp {
    fn send(&mut self, msg: &Value) {
        let stdin = self.stdin.as_mut().unwrap();
        writeln!(stdin, "{msg}").unwrap();
        stdin.flush().unwrap();
    }

    /// Sends a request and returns its response. Every line on stdout must
    /// be a JSON-RPC message.
    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        loop {
            let mut line = String::new();
            let n = self.stdout.read_line(&mut line).unwrap();
            assert!(n > 0, "dwhy-mcp closed stdout");
            let msg: Value = serde_json::from_str(&line)
                .unwrap_or_else(|e| panic!("stdout line is not JSON-RPC: {e}: {line:?}"));
            assert_eq!(msg["jsonrpc"], "2.0", "{msg}");
            if msg["id"] == id {
                return msg;
            }
        }
    }

    fn tools(&mut self) -> Vec<Value> {
        let r = self.request("tools/list", json!({}));
        r["result"]["tools"].as_array().unwrap().clone()
    }

    fn call(&mut self, name: &str, args: Value) -> Called {
        let r = self.request("tools/call", json!({"name": name, "arguments": args}));
        let result = &r["result"];
        assert!(result.is_object(), "{r}");
        let blocks = result["content"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| {
                assert_eq!(b["type"], "text", "{b}");
                let text = b["text"].as_str().unwrap();
                serde_json::from_str(text).unwrap_or_else(|e| panic!("{e}: {text}"))
            })
            .collect();
        Called {
            is_error: result["isError"] == true,
            blocks,
        }
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        // EOF on stdin ends the session.
        drop(self.stdin.take());
        let _ = self.child.wait();
    }
}

/// The audit log's records.
fn audit_records(h: &Home) -> Vec<Value> {
    fs::read_to_string(h.audit())
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

/// A plan of every tier the home has.
fn plan_all(mcp: &mut Mcp, h: &Home) -> Value {
    let plan = mcp
        .call(
            "plan",
            json!({
                "paths": [h.root()],
                "tier": "review",
                "detectors": ["user-cache", "stale-tree", "cargo-target"],
            }),
        )
        .ok()
        .clone();
    let tiers: Vec<&str> = plan["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["finding"]["tier"].as_str().unwrap())
        .collect();
    assert_eq!(tiers, ["rebuildable", "regenerable", "review"], "{plan}");
    plan
}

fn outcomes(report: &Value) -> Vec<(String, String)> {
    let mut o: Vec<(String, String)> = report["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            (
                i["tier"].as_str().unwrap().to_string(),
                i["outcome"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    o.sort();
    o
}

fn names(tools: &[Value]) -> Vec<&str> {
    let mut n: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    n.sort();
    n
}

#[test]
fn lists_six_tools_and_apply_takes_no_tier_or_confirmation() {
    let h = Home::new();
    let mut mcp = h.server(&[]);
    let tools = mcp.tools();
    assert_eq!(
        names(&tools),
        ["apply", "diff", "explain", "plan", "scan", "watch"]
    );
    let apply = tools.iter().find(|t| t["name"] == "apply").unwrap();
    let props = apply["inputSchema"]["properties"].as_object().unwrap();
    let mut keys: Vec<&str> = props.keys().map(String::as_str).collect();
    keys.sort();
    assert_eq!(keys, ["dry_run", "plan"], "{apply}");
    assert_eq!(apply["annotations"]["destructiveHint"], true, "{apply}");
    for t in &tools {
        let props = t["inputSchema"]["properties"].as_object().unwrap();
        assert!(!props.contains_key("max_tier"), "{t}");
        assert!(!props.contains_key("confirm"), "{t}");
    }
    let explain = tools.iter().find(|t| t["name"] == "explain").unwrap();
    assert_eq!(explain["annotations"]["readOnlyHint"], true, "{explain}");

    // Smuggling a tier or a confirmation in is a usage error, not ignored.
    let plan = plan_all(&mut mcp, &h);
    for extra in [json!({"max_tier": "review"}), json!({"confirm": ["f_x"]})] {
        let mut args = json!({"plan": plan});
        args.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let called = mcp.call("apply", args);
        let e = called.err();
        assert_eq!(e["kind"], "usage", "{e}");
        assert_eq!(e["exit_code"], 1, "{e}");
    }
    assert!(h.pip().exists() && h.target().exists() && h.scratch().exists());
    assert!(!h.audit().exists());
}

#[test]
fn read_only_has_no_apply_and_refuses_calls_to_it() {
    let h = Home::new();
    let mut mcp = h.server(&["--read-only"]);
    assert_eq!(
        names(&mcp.tools()),
        ["diff", "explain", "plan", "scan", "watch"]
    );
    let plan = plan_all(&mut mcp, &h);
    let called = mcp.call("apply", json!({"plan": plan}));
    let e = called.err();
    assert_eq!(e["kind"], "refused", "{e}");
    assert_eq!(e["exit_code"], 3, "{e}");
    assert!(
        e["message"].as_str().unwrap().contains("--read-only"),
        "{e}"
    );
    assert!(h.pip().exists() && h.target().exists() && h.scratch().exists());
    assert!(!h.audit().exists());
}

#[test]
fn scan_explain_diff_watch_and_plan() {
    let h = Home::new();
    let root = h.root();
    let target = h.target().to_str().unwrap().to_string();
    let mut mcp = h.server(&[]);
    let det = json!(["cargo-target"]);

    // Summary by default.
    let called = mcp.call("scan", json!({"paths": [root], "detectors": det}));
    let r = called.ok();
    assert_eq!(r["schema"], "diskwhy/v1");
    assert!(r["findings_summary"].is_object(), "{r}");
    assert!(r["scan"]["dirs_omitted"].is_u64(), "{r}");
    assert_eq!(r["findings"][0]["path"], target.as_str(), "{r}");
    assert!(r.get("snapshot").is_none());
    assert!(!h.snapshots().exists(), "no snapshot unless asked");

    // The full report, saving a snapshot.
    let called = mcp.call(
        "scan",
        json!({"paths": [root], "detectors": det, "summary": false, "snapshot": true}),
    );
    assert_eq!(called.blocks.len(), 1);
    let r = called.ok();
    assert!(r.get("findings_summary").is_none(), "{r}");
    assert!(r["scan"].get("dirs_omitted").is_none(), "{r}");
    let id = r["snapshot"]["id"].as_str().unwrap().to_string();
    assert_eq!(fs::read_dir(h.snapshots()).unwrap().count(), 1);

    // Explain the cargo target by path: the finding with its guards.
    let called = mcp.call("explain", json!({"target": target, "detectors": det}));
    let r = called.ok();
    assert_eq!(r["resolved"]["via"], "path", "{r}");
    assert_eq!(r["finding"]["detector"], "cargo-target", "{r}");
    assert_eq!(r["finding"]["tier"], "rebuildable", "{r}");
    assert!(
        !r["finding"]["guards"].as_array().unwrap().is_empty(),
        "{r}"
    );

    // Diff with the snapshot after the target grew.
    fs::write(h.target().join("debug/more"), vec![3u8; 1 << 20]).unwrap();
    let called = mcp.call("diff", json!({"min_change": "0", "detectors": det}));
    let r = called.ok();
    assert_eq!(r["schema"], "diskwhy/v1");
    assert_eq!(r["since"]["id"], id.as_str(), "{r}");
    assert_eq!(r["roots"], json!([root]));
    assert_eq!(r["findings"][0]["name"], target.as_str(), "{r}");
    assert!(
        r["findings"][0]["change"].as_i64().unwrap() >= 1 << 20,
        "{r}"
    );
    assert!(
        r["notes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n.as_str().unwrap().contains("not recorded in snapshots")),
        "{r}"
    );
    let called = mcp.call("diff", json!({"cross_filesystems": true}));
    assert_eq!(called.err()["kind"], "usage");

    // Watch for a second.
    let called = mcp.call(
        "watch",
        json!({"paths": [root], "duration": "1s", "no_docker": true}),
    );
    let r = called.ok();
    assert_eq!(r["schema"], "diskwhy/v1");
    assert_eq!(r["for_secs"], 1, "{r}");
    assert_eq!(r["docker_compared"], false, "{r}");
    let called = mcp.call("watch", json!({"duration": "0s"}));
    assert_eq!(called.err()["kind"], "usage");

    // Plan by goal; nothing is written.
    let called = mcp.call(
        "plan",
        json!({"paths": [root], "detectors": det, "tier": "rebuildable", "free": "1M"}),
    );
    let r = called.ok();
    assert_eq!(r["schema"], "diskwhy/v1");
    assert_eq!(r["items"][0]["finding"]["path"], target.as_str(), "{r}");
    assert!(r["goal"].is_object(), "{r}");
    let called = mcp.call("plan", json!({"paths": [root], "free": "0"}));
    let e = called.err();
    assert_eq!(e["kind"], "usage", "{e}");
    assert_eq!(e["exit_code"], 1, "{e}");
    assert!(e["message"].as_str().unwrap().contains("'free'"), "{e}");
    let called = mcp.call("plan", json!({"free": "1M", "select": ["f_x"]}));
    assert_eq!(called.err()["kind"], "usage");
    let called = mcp.call("plan", json!({"tier": "blocked"}));
    assert_eq!(called.err()["kind"], "usage");

    // A runtime failure is an error, not a usage error.
    let called = mcp.call("scan", json!({"paths": [root], "detectors": ["nope"]}));
    assert_eq!(called.err()["kind"], "error");
    assert_eq!(fs::read_dir(h.snapshots()).unwrap().count(), 1);
    assert!(!h.audit().exists());
}

#[test]
fn apply_removes_regenerable_only_by_default() {
    let h = Home::new();
    let mut mcp = h.server(&[]);
    let plan = plan_all(&mut mcp, &h);

    // A dry run removes nothing and writes no audit log.
    let called = mcp.call("apply", json!({"plan": plan, "dry_run": true}));
    let r = called.ok();
    assert_eq!(r["dry_run"], true);
    assert!(r["would_free"].as_u64().unwrap() >= 3 << 20, "{r}");
    assert!(r.get("audit_log").is_none(), "{r}");
    assert_eq!(
        outcomes(r),
        [
            ("rebuildable".into(), "refused".into()),
            ("regenerable".into(), "would_remove".into()),
            ("review".into(), "refused".into()),
        ]
    );
    assert!(h.pip().exists() && h.target().exists() && h.scratch().exists());
    assert!(!h.audit().exists());

    let called = mcp.call("apply", json!({"plan": plan}));
    let r = called.ok();
    assert_eq!(r["dry_run"], false);
    assert_eq!(r["max_tier"], "regenerable");
    assert_eq!(r["confirm"], json!([]));
    assert!(r.get("would_free").is_none(), "{r}");
    assert_eq!(r["audit_log"], h.audit().to_str().unwrap(), "{r}");
    assert_eq!(
        outcomes(r),
        [
            ("rebuildable".into(), "refused".into()),
            ("regenerable".into(), "removed".into()),
            ("review".into(), "refused".into()),
        ]
    );
    assert!(!h.pip().exists());
    assert!(h.target().exists() && h.scratch().exists());

    let records = audit_records(&h);
    assert!(!records.is_empty());
    for rec in &records {
        assert_eq!(rec["yes"], true, "{rec}");
        assert_eq!(rec["tty"], false, "{rec}");
        assert_eq!(rec["max_tier"], "regenerable", "{rec}");
        assert_eq!(rec["confirm"], json!([]), "{rec}");
    }
    assert!(
        records
            .iter()
            .any(|r| r["detector"] == "user-cache" && r["outcome"] == "removed")
    );
}

#[test]
fn a_rebuildable_server_never_removes_review_items_and_policy_lowers_it() {
    let h = Home::new();
    let mut mcp = h.server(&["--max-tier", "rebuildable"]);
    let plan = plan_all(&mut mcp, &h);

    // The user's policy.toml lowers the server's ceiling.
    h.write_policy("max_tier = \"regenerable\"\n");
    let called = mcp.call("apply", json!({"plan": plan, "dry_run": true}));
    let r = called.ok();
    assert_eq!(r["max_tier"], "regenerable", "{r}");
    assert_eq!(
        outcomes(r),
        [
            ("rebuildable".into(), "refused".into()),
            ("regenerable".into(), "would_remove".into()),
            ("review".into(), "refused".into()),
        ]
    );

    // A policy file that does not parse stops apply (and the rest) cold.
    h.write_policy("max_tier = \n");
    let called = mcp.call("apply", json!({"plan": plan}));
    let e = called.err();
    assert_eq!(e["kind"], "error", "{e}");
    assert_eq!(e["exit_code"], 1, "{e}");
    let called = mcp.call(
        "scan",
        json!({"paths": [h.root()], "detectors": ["cargo-target"]}),
    );
    assert_eq!(called.err()["kind"], "error");
    assert!(h.pip().exists() && h.target().exists() && h.scratch().exists());
    assert!(!h.audit().exists());

    // Without it: rebuildable items go, review items still do not.
    fs::remove_file(h.base.join("config/diskwhy/policy.toml")).unwrap();
    let called = mcp.call("apply", json!({"plan": plan}));
    let r = called.ok();
    assert_eq!(r["max_tier"], "rebuildable", "{r}");
    assert_eq!(
        outcomes(r),
        [
            ("rebuildable".into(), "removed".into()),
            ("regenerable".into(), "removed".into()),
            ("review".into(), "refused".into()),
        ]
    );
    assert!(!h.pip().exists() && !h.target().exists());
    assert!(h.scratch().join("old/blob").exists());
    for rec in audit_records(&h) {
        assert_eq!(rec["max_tier"], "rebuildable", "{rec}");
        assert_eq!(rec["tty"], false, "{rec}");
    }
}

#[test]
fn apply_refuses_an_expired_plan_and_rejects_junk() {
    let h = Home::new();
    let mut mcp = h.server(&[]);
    let mut plan = plan_all(&mut mcp, &h);
    plan["created_at"] = "2026-01-01T00:00:00Z".into();
    plan["expires_at"] = "2026-01-01T01:00:00Z".into();
    for dry_run in [false, true] {
        let called = mcp.call("apply", json!({"plan": plan, "dry_run": dry_run}));
        let e = called.err();
        assert_eq!(e["kind"], "refused", "{e}");
        assert_eq!(e["exit_code"], 3, "{e}");
        let message = e["message"].as_str().unwrap();
        let hint = e["hint"].as_str().unwrap();
        assert!(message.contains("expired"), "{e}");
        assert!(hint.contains("`plan`"), "{e}");
        assert!(!message.contains("dwhy") && !hint.contains("dwhy"), "{e}");
    }
    let called = mcp.call("apply", json!({"plan": {}}));
    assert_eq!(called.err()["kind"], "error");
    let text = serde_json::to_string(&plan_all(&mut mcp, &h)).unwrap();
    let called = mcp.call("apply", json!({"plan": text, "dry_run": true}));
    assert_eq!(called.err()["kind"], "usage");
    let called = mcp.call("apply", json!({}));
    assert_eq!(called.err()["kind"], "usage");
    assert!(h.pip().exists() && h.target().exists() && h.scratch().exists());
    assert!(!h.audit().exists());
}
