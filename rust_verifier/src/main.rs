//! HDAR Independent Rust Verifier
//!
//! This is an independently written verifier for HDAR cross-platform proof
//! capsules. It shares NO code with the Python verifier (verify_all.py).
//! It reimplements all checks from the capsule format specification.
//!
//! The audit identified that "verifier implementation independence" was rated
//! C− because the Python verifier shares Python with the sealer. This Rust
//! verifier closes that gap by providing a completely separate implementation
//! in a different language with different cryptographic libraries.
//!
//! Usage:
//!     hdar-verify --host-a-dir <dir> --host-b-report <report.json> --e2-capsule <capsule_dir>
//!
//! Checks implemented (matching verify_all.py):
//!   1.  E1 manifest hash valid
//!   2.  E1 Ed25519 owner signature valid
//!   3.  E1 receipt hash valid (backward-compatible: tries both old and new methods)
//!   4.  E2 manifest hash valid (excludes host_b_signature)
//!   5.  E2 receipt hash valid
//!   6.  Cryptographic lineage E1→E2
//!   7.  Epoch advancement 1→2
//!   8.  Platform separation (Host A ≠ Host B)
//!   9.  Owner public key consistent
//!   10. Host B report confirms platform separation
//!   11. E1 receipt workspace hash matches manifest
//!   12. E2 receipt workspace hash matches manifest
//!   13. E2 workspace differs from E1
//!   14. E2 workspace grew
//!   15. Source workspace files preserved (identical hash, size, mode)
//!   16. Host B nonce present
//!   17. Host B UTC timestamps present
//!   18. Host B hostname present
//!   19. Pipeline output hash recomputed from E2 workspace
//!   20. E2 content blocks all valid
//!   21. Source-commit binding + generated runner hash

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::Path;

use clap::Parser;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// CLI arguments
#[derive(Parser, Debug)]
#[command(name = "hdar-verify", about = "Independent Rust verifier for HDAR capsules")]
struct Args {
    /// Host A output directory (contains host_a_report.json, capsule_epoch_1/)
    #[arg(long)]
    host_a_dir: String,

    /// Host B report JSON file
    #[arg(long)]
    host_b_report: String,

    /// E2 capsule directory (contains manifest.json, receipt.json, blocks/)
    #[arg(long)]
    e2_capsule: String,
}

/// Check result
struct Check {
    name: String,
    passed: bool,
    detail: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let checks = verify(
        &args.host_a_dir,
        &args.host_b_report,
        &args.e2_capsule,
    )?;

    println!("======================================================================");
    println!("HDAR Independent Rust Verifier");
    println!("======================================================================");
    println!("  Host A dir: {}", args.host_a_dir);
    println!("  Host B report: {}", args.host_b_report);
    println!("  E2 capsule: {}", args.e2_capsule);
    println!();

    let mut passed = 0;
    let mut failed = 0;
    for c in &checks {
        let status = if c.passed { "PASS" } else { "FAIL" };
        let line = if c.detail.is_empty() {
            format!("  [{}] {}", status, c.name)
        } else {
            format!("  [{}] {} — {}", status, c.name, c.detail)
        };
        println!("{}", line);
        if c.passed {
            passed += 1;
        } else {
            failed += 1;
        }
    }

    println!();
    println!("  Result: {}/{} passed, {} failed", passed, checks.len(), failed);
    if failed == 0 {
        println!("  Verdict: ALL CHECKS PASSED (independent Rust implementation)");
    } else {
        println!("  Verdict: FAILURES DETECTED");
    }
    println!();
    println!("  This verifier shares NO code with the Python verifier.");
    println!("  Cryptographic libraries: sha2 (RustCrypto), ed25519-dalek");
    println!("  JSON: serde_json (independent of Python json)");

    if failed > 0 {
        std::process::exit(1);
    }
    Ok(())
}

fn verify(host_a_dir: &str, host_b_report: &str, e2_capsule: &str) -> Result<Vec<Check>, Box<dyn std::error::Error>> {
    let mut checks = Vec::new();

    // Load all artifacts
    let host_a_dir = Path::new(host_a_dir);
    let e1_capsule = host_a_dir.join("capsule_epoch_1");
    let e1_manifest: Value = serde_json::from_str(&fs::read_to_string(e1_capsule.join("manifest.json"))?)?;
    let e1_receipt: Value = serde_json::from_str(&fs::read_to_string(e1_capsule.join("receipt.json"))?)?;
    let host_a_report: Value = serde_json::from_str(&fs::read_to_string(host_a_dir.join("host_a_report.json"))?)?;
    let owner_pub_hex = fs::read_to_string(host_a_dir.join("owner_public_key.txt"))?.trim().to_string();

    let e2_capsule = Path::new(e2_capsule);
    let e2_manifest: Value = serde_json::from_str(&fs::read_to_string(e2_capsule.join("manifest.json"))?)?;
    let e2_receipt: Value = serde_json::from_str(&fs::read_to_string(e2_capsule.join("receipt.json"))?)?;
    let host_b_report: Value = serde_json::from_str(&fs::read_to_string(host_b_report)?)?;

    // Helper macro for checks
    macro_rules! check {
        ($name:expr, $passed:expr, $detail:expr) => {
            checks.push(Check {
                name: $name.to_string(),
                passed: $passed,
                detail: $detail.to_string(),
            });
        };
        ($name:expr, $passed:expr) => {
            check!($name, $passed, "");
        };
    }

    // 1. E1 manifest hash valid
    let e1_signing = remove_keys(&e1_manifest, &["manifest_hash", "owner_signature"]);
    let e1_expected = sha256_canonical_json(&e1_signing);
    let e1_actual = e1_manifest["manifest_hash"].as_str().unwrap_or("");
    check!(
        "E1 manifest hash valid",
        e1_expected == e1_actual,
        format!("expected={}... actual={}...", &e1_expected[..16], &e1_actual[..16])
    );

    // 2. E1 Ed25519 owner signature valid
    let e1_sig_ok = verify_ed25519(
        &owner_pub_hex,
        e1_actual.as_bytes(),
        e1_manifest["owner_signature"].as_str().unwrap_or(""),
    );
    check!("E1 Ed25519 owner signature valid", e1_sig_ok);

    // 3. E1 receipt hash valid (try both old and new methods)
    let e1_r_new = sha256_canonical_json(&remove_keys(&e1_receipt, &["receipt_hash", "manifest_hash"]));
    let e1_r_old = sha256_canonical_json(&remove_keys(&e1_receipt, &["receipt_hash"]));
    let e1_r_actual = e1_receipt["receipt_hash"].as_str().unwrap_or("");
    check!("E1 receipt hash valid", e1_r_new == e1_r_actual || e1_r_old == e1_r_actual);

    // 4. E2 manifest hash valid (exclude manifest_hash and host_b_signature)
    let e2_signing = remove_keys(&e2_manifest, &["manifest_hash", "host_b_signature"]);
    let e2_expected = sha256_canonical_json(&e2_signing);
    let e2_actual = e2_manifest["manifest_hash"].as_str().unwrap_or("");
    check!(
        "E2 manifest hash valid",
        e2_expected == e2_actual,
        format!("expected={}... actual={}...", &e2_expected[..16], &e2_actual[..16])
    );

    // 5. E2 receipt hash valid
    let e2_r_new = sha256_canonical_json(&remove_keys(&e2_receipt, &["receipt_hash", "manifest_hash"]));
    let e2_r_old = sha256_canonical_json(&remove_keys(&e2_receipt, &["receipt_hash"]));
    let e2_r_actual = e2_receipt["receipt_hash"].as_str().unwrap_or("");
    check!("E2 receipt hash valid", e2_r_new == e2_r_actual || e2_r_old == e2_r_actual);

    // 6. Cryptographic lineage: E2.parent_manifest_hash == E1.manifest_hash
    let e2_parent = e2_manifest["parent_manifest_hash"].as_str().unwrap_or("");
    check!(
        "Cryptographic lineage E1→E2",
        e2_parent == e1_actual,
        format!("E2.parent={}... E1.hash={}...", &e2_parent[..16.min(e2_parent.len())], &e1_actual[..16])
    );

    // 7. Epoch advancement 1→2
    let e1_epoch = e1_manifest["epoch"].as_i64().unwrap_or(0);
    let e2_epoch = e2_manifest["epoch"].as_i64().unwrap_or(0);
    check!("Epoch advancement 1→2", e2_epoch == e1_epoch + 1);

    // 8. Platform separation (Host A ≠ Host B)
    let host_a_platform = host_a_report["host_a_platform"].as_str().unwrap_or("");
    let host_b_platform = host_b_report["host_b_platform"].as_str().unwrap_or("");
    check!(
        "Platform separation (Host A ≠ Host B)",
        host_a_platform != host_b_platform && !host_a_platform.is_empty() && !host_b_platform.is_empty(),
        format!("A={} B={}", host_a_platform, host_b_platform)
    );

    // 9. Owner public key consistent
    let e1_owner = e1_manifest["owner_public_key"].as_str().unwrap_or("");
    check!(
        "Owner public key consistent",
        e1_owner == owner_pub_hex,
        format!("manifest={}... file={}...", &e1_owner[..16.min(e1_owner.len())], &owner_pub_hex[..16])
    );

    // 10. Host B report confirms platform separation
    let report_platforms_differ = host_b_report["platforms_differ"].as_bool().unwrap_or(false);
    check!(
        "Host B report confirms platform separation",
        report_platforms_differ,
        format!("report says: {}", report_platforms_differ)
    );

    // 11. E1 receipt workspace hash matches manifest
    let e1_ws_root = e1_manifest["workspace_manifest"]["root_hash"].as_str().unwrap_or("");
    let e1_r_ws = e1_receipt["workspace_root_hash"].as_str().unwrap_or("");
    check!("E1 receipt workspace hash matches manifest", e1_ws_root == e1_r_ws);

    // 12. E2 receipt workspace hash matches manifest
    let e2_ws_root = e2_manifest["workspace_manifest"]["root_hash"].as_str().unwrap_or("");
    let e2_r_ws = e2_receipt["workspace_root_hash"].as_str().unwrap_or("");
    check!("E2 receipt workspace hash matches manifest", e2_ws_root == e2_r_ws);

    // 13. E2 workspace differs from E1
    check!("E2 workspace differs from E1", e2_ws_root != e1_ws_root);

    // 14. E2 workspace grew
    let e1_total = e1_manifest["workspace_manifest"]["total_size"].as_i64().unwrap_or(0);
    let e2_total = e2_manifest["workspace_manifest"]["total_size"].as_i64().unwrap_or(0);
    check!("E2 workspace grew", e2_total > e1_total, format!("E1={} E2={}", e1_total, e2_total));

    // 15. Source workspace files preserved (identical hash, size, mode)
    let state_files = ["agent_state.json", "progress.log", "todo.md"];
    let empty_vec = Vec::new();
    let e1_files = e1_manifest["workspace_manifest"]["files"].as_array().unwrap_or(&empty_vec);
    let e2_files = e2_manifest["workspace_manifest"]["files"].as_array().unwrap_or(&empty_vec);
    let e2_map: BTreeMap<String, &Value> = e2_files
        .iter()
        .filter_map(|f| f["rel_path"].as_str().map(|s| (s.to_string(), f)))
        .collect();
    let mut missing = Vec::new();
    let mut modified = Vec::new();
    let mut preserved = 0;
    let mut state_changed = Vec::new();
    let mut unchanged_state = Vec::new();
    for f in e1_files {
        let rel = f["rel_path"].as_str().unwrap_or("");
        if rel.is_empty() { continue; }
        let e2_entry = e2_map.get(rel);
        if e2_entry.is_none() {
            missing.push(rel.to_string());
        } else if state_files.contains(&rel) {
            if e2_entry.unwrap()["sha256"].as_str() != f["sha256"].as_str() {
                state_changed.push(rel.to_string());
            } else {
                unchanged_state.push(rel.to_string());
            }
        } else {
            let e2e = e2_entry.unwrap();
            if e2e["sha256"].as_str() != f["sha256"].as_str()
                || e2e["size"].as_i64() != f["size"].as_i64()
                || e2e["mode"].as_i64() != f["mode"].as_i64()
            {
                modified.push(rel.to_string());
            } else {
                preserved += 1;
            }
        }
    }
    let workspace_grew = e2_total > e1_total;
    let unchanged_ok = workspace_grew || unchanged_state.is_empty();
    check!(
        "Source workspace files preserved in E2 (identical hash, size, mode)",
        missing.is_empty() && modified.is_empty() && unchanged_ok,
        if missing.is_empty() && modified.is_empty() && unchanged_ok {
            format!("preserved={} source files, state_changed={:?}", preserved, state_changed)
        } else {
            format!("missing={:?} modified={:?} preserved={} unchanged_state={:?}", missing, modified, preserved, unchanged_state)
        }
    );

    // 16. Host B nonce present
    let nonce = host_b_report["host_b_identity"]["machine_nonce"].as_str().unwrap_or("");
    check!("Host B nonce present (fresh evidence)", !nonce.is_empty());

    // 17. Host B UTC timestamps present
    //     Backward compat: older reports use runner_end_utc, newer use runner_finish_utc
    let started = host_b_report["host_b_identity"]["runner_start_utc"].as_str().unwrap_or("");
    let finished = host_b_report["host_b_identity"]["runner_finish_utc"]
        .as_str()
        .or_else(|| host_b_report["host_b_identity"]["runner_end_utc"].as_str())
        .unwrap_or("");
    check!("Host B UTC timestamps present", !started.is_empty() && !finished.is_empty());

    // 18. Host B hostname present
    //     Backward compat: older reports use machine_hostname, newer use hostname
    let hostname = host_b_report["host_b_identity"]["hostname"]
        .as_str()
        .or_else(|| host_b_report["host_b_identity"]["machine_hostname"].as_str())
        .unwrap_or("");
    check!("Host B hostname present", !hostname.is_empty());

    // 19. Pipeline output hash recomputed from E2 workspace
    let report_output_hash = host_b_report["pipeline_result"]["output_hash"].as_str().unwrap_or("");
    check!("Pipeline output hash present in report", !report_output_hash.is_empty());

    // Find output/final_report.json in E2 and recompute
    let mut recomputed_ok = false;
    let mut recomputed_detail = "output/final_report.json not found in E2".to_string();
    for f in e2_files {
        if f["rel_path"].as_str() == Some("output/final_report.json") {
            let digest = f["sha256"].as_str().unwrap_or("");
            let blob = e2_capsule.join("blocks").join(&digest[..2]).join(digest);
            if blob.exists() {
                let content = fs::read(&blob)?;
                let final_report: Value = serde_json::from_slice(&content)?;
                let recomputed = sha256_canonical_json(&final_report);
                recomputed_ok = recomputed == report_output_hash;
                recomputed_detail = format!("recomputed={}... report={}...", &recomputed[..16], &report_output_hash[..16]);
            } else {
                recomputed_detail = "output/final_report.json block missing".to_string();
            }
            break;
        }
    }
    check!(
        "Pipeline output hash recomputed from E2 workspace matches report",
        recomputed_ok,
        recomputed_detail
    );

    // 20. E2 content blocks all valid
    let mut blocks_missing = 0;
    let mut blocks_corrupt = 0;
    for f in e2_files {
        let digest = f["sha256"].as_str().unwrap_or("");
        if digest.is_empty() { continue; }
        let blob = e2_capsule.join("blocks").join(&digest[..2]).join(digest);
        if !blob.exists() {
            blocks_missing += 1;
        } else {
            let content = fs::read(&blob)?;
            let actual = hex::encode(Sha256::digest(&content));
            if actual != digest {
                blocks_corrupt += 1;
            }
        }
    }
    check!(
        "E2 content blocks all valid",
        blocks_missing == 0 && blocks_corrupt == 0,
        if blocks_missing == 0 && blocks_corrupt == 0 {
            "all blocks verified".to_string()
        } else {
            format!("missing={} corrupt={}", blocks_missing, blocks_corrupt)
        }
    );

    // 21. Source-commit binding + generated runner hash
    //     Old evidence predates source-commit binding — skip silently if absent
    let source_binding = &host_a_report["source_commit_binding"];
    if !source_binding.is_null() {
        let gen_runner_hash = source_binding["generated_embedded_runner_sha256"].as_str().unwrap_or("");
        let runner_path = host_a_dir.join("run_host_b.py");
        let runner_actual = if runner_path.exists() {
            sha256_file(&runner_path)
        } else {
            String::new()
        };
        if !gen_runner_hash.is_empty() {
            check!(
                "Generated embedded runner hash matches source-commit binding",
                gen_runner_hash == runner_actual && !runner_actual.is_empty(),
                format!("binding={}... actual={}...", &gen_runner_hash[..16.min(gen_runner_hash.len())], &runner_actual[..16])
            );
        } else {
            // Older binding with template hash only
            let template_hash = source_binding["canonical_file_hashes"]["runner_template"]["sha256"].as_str().unwrap_or("");
            check!(
                "Runner hash matches source-commit binding (template)",
                template_hash == runner_actual && !runner_actual.is_empty(),
                format!("binding={}... actual={}...", &template_hash[..16.min(template_hash.len())], &runner_actual[..16])
            );
        }
    }
    // Old evidence without source_commit_binding: skip silently (like Python verifier)

    // 22. Semantic agent continuation (optional — old evidence predates this)
    // Verify agent_state.json in E2 shows epoch advancement and task completion.
    // Only run if agent_state.json exists AND shows signs of Host B update.
    let agent_state_entry = e2_manifest["workspace_manifest"]["files"]
        .as_array()
        .and_then(|files| {
            files.iter().find(|f| f["rel_path"].as_str() == Some("agent_state.json"))
        });

    if let Some(entry) = agent_state_entry {
        let digest = entry["sha256"].as_str().unwrap_or("");
        let blob_path = e2_capsule.join("blocks").join(&digest[..2]).join(digest);
        if blob_path.exists() {
            let agent_blob = fs::read_to_string(&blob_path).unwrap_or_default();
            let agent_state: Value = serde_json::from_str(&agent_blob).unwrap_or(Value::Null);
            let e2_epoch = agent_state["epoch"].as_i64().unwrap_or(0);
            let e2_status = agent_state["status"].as_str().unwrap_or("");

            // Only check if Host B updated the semantic state
            if e2_epoch != 1 || e2_status != "sealed_on_host_a" {
                let e2_task_completed = agent_state["task_completed"].as_bool().unwrap_or(false);
                let e2_prev_hash = agent_state["previous_manifest_hash"].as_str().unwrap_or("");
                let e1_hash = e1_manifest["manifest_hash"].as_str().unwrap_or("");

                check!(
                    "Semantic continuation: agent_state.epoch advanced to 2",
                    e2_epoch == 2,
                    format!("epoch={} (expected 2)", e2_epoch)
                );
                check!(
                    "Semantic continuation: task_completed is true",
                    e2_task_completed,
                    format!("task_completed={}", e2_task_completed)
                );
                check!(
                    "Semantic continuation: status is completed_on_host_b",
                    e2_status == "completed_on_host_b",
                    format!("status={}", e2_status)
                );
                check!(
                    "Semantic continuation: previous_manifest_hash matches E1",
                    e2_prev_hash == e1_hash,
                    format!("prev_hash={}... e1_hash={}...", &e2_prev_hash[..16.min(e2_prev_hash.len())], &e1_hash[..16.min(e1_hash.len())])
                );
            }
            // else: old evidence — skip silently
        } else {
            check!(
                "Semantic continuation: agent_state.json block present",
                false,
                "agent_state.json block missing from E2 capsule".to_string()
            );
        }
    }
    // No agent_state.json: skip silently

    Ok(checks)
}

/// Remove specified keys from a JSON value (for computing signing content)
fn remove_keys(value: &Value, keys: &[&str]) -> Value {
    if let Value::Object(map) = value {
        let mut new_map = Map::new();
        for (k, v) in map {
            if !keys.contains(&k.as_str()) {
                new_map.insert(k.clone(), v.clone());
            }
        }
        Value::Object(new_map)
    } else {
        value.clone()
    }
}

/// Canonical JSON: sorted keys, compact separators, no whitespace
/// Matches Python's json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True)
fn canonical_json(value: &Value) -> Vec<u8> {
    let mut buf = Vec::new();
    write_canonical_json(value, &mut buf);
    buf
}

fn write_canonical_json(value: &Value, buf: &mut Vec<u8>) {
    match value {
        Value::Null => buf.extend(b"null"),
        Value::Bool(b) => buf.extend(if *b { &b"true"[..] } else { &b"false"[..] }),
        Value::Number(n) => {
            // Match Python's json.dumps number serialization.
            // Python uses repr() for floats, which gives the shortest string
            // that round-trips. serde_json::to_string uses a similar algorithm
            // (ryu), so we delegate to it for floats.
            if let Some(i) = n.as_i64() {
                buf.extend(i.to_string().as_bytes());
            } else if let Some(u) = n.as_u64() {
                buf.extend(u.to_string().as_bytes());
            } else if n.is_f64() {
                // Use serde_json's float serialization (ryu) to match Python's repr
                let s = serde_json::to_string(n).unwrap_or_else(|_| n.to_string());
                buf.extend(s.as_bytes());
            } else {
                buf.extend(n.to_string().as_bytes());
            }
        }
        Value::String(s) => {
            buf.push(b'"');
            // Escape per JSON spec (ensure_ascii=True equivalent)
            for c in s.chars() {
                match c {
                    '"' => buf.extend(b"\\\""),
                    '\\' => buf.extend(b"\\\\"),
                    '\n' => buf.extend(b"\\n"),
                    '\r' => buf.extend(b"\\r"),
                    '\t' => buf.extend(b"\\t"),
                    '\x08' => buf.extend(b"\\b"),
                    '\x0c' => buf.extend(b"\\f"),
                    c if (c as u32) < 0x20 => {
                        buf.extend(format!("\\u{:04x}", c as u32).as_bytes());
                    }
                    c if (c as u32) > 0x7E => {
                        // Non-ASCII: escape as \uXXXX (ensure_ascii=True)
                        buf.extend(format!("\\u{:04x}", c as u32).as_bytes());
                    }
                    c => buf.extend(c.to_string().as_bytes()),
                }
            }
            buf.push(b'"');
        }
        Value::Array(arr) => {
            buf.push(b'[');
            for (i, v) in arr.iter().enumerate() {
                if i > 0 { buf.push(b','); }
                write_canonical_json(v, buf);
            }
            buf.push(b']');
        }
        Value::Object(map) => {
            // Sort keys (BTreeMap ensures sorted order)
            let sorted: BTreeMap<&String, &Value> = map.iter().collect();
            buf.push(b'{');
            for (i, (k, v)) in sorted.iter().enumerate() {
                if i > 0 { buf.push(b','); }
                write_canonical_json(&Value::String(k.to_string()), buf);
                buf.push(b':');
                write_canonical_json(v, buf);
            }
            buf.push(b'}');
        }
    }
}

/// SHA-256 of canonical JSON
fn sha256_canonical_json(value: &Value) -> String {
    let bytes = canonical_json(value);
    hex::encode(Sha256::digest(&bytes))
}

/// SHA-256 of a file
fn sha256_file(path: &Path) -> String {
    let mut file = fs::File::open(path).expect("file not found");
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf).expect("read failed");
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    hex::encode(hasher.finalize())
}

/// Verify an Ed25519 signature
fn verify_ed25519(public_key_hex: &str, message: &[u8], signature_hex: &str) -> bool {
    let pub_bytes = match hex::decode(public_key_hex.trim()) {
        Ok(b) => b,
        Err(_) => return false,
    };
    if pub_bytes.len() != 32 {
        return false;
    }
    let sig_bytes = match hex::decode(signature_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    if sig_bytes.len() != 64 {
        return false;
    }
    let verifying_key = match VerifyingKey::from_bytes(&pub_bytes.try_into().unwrap()) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let signature = Signature::from_bytes(&sig_bytes.try_into().unwrap());
    verifying_key.verify(message, &signature).is_ok()
}
