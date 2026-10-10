// Director socket control tests for `cowproof rule` and `cowproof note`.
#![cfg(unix)]

use cowproof_run::{
    director,
    escalate::{Ask, AskKind, EscalationId, Origin, Queue, Verdict},
};
use serde_json::json;
use std::fs;
use std::os::unix::fs::FileTypeExt;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::process::Command;

struct TestClock;

impl cowproof_run::escalate::Clock for TestClock {
    fn now(&self) -> std::time::SystemTime {
        std::time::SystemTime::now()
    }
}

async fn test_ask_then_rule() {
    // Create a temporary directory for the queue
    let tmp = TempDir::new().unwrap();
    let control_dir = tmp.path().join("control");
    fs::create_dir_all(&control_dir).unwrap();

    // Create the queue and an ask
    let queue = Arc::new(Mutex::new(
        Queue::new(&control_dir, Box::new(TestClock)).unwrap(),
    ));

    {
        let mut q = queue.lock().unwrap();
        let ask = Ask {
            kind: AskKind::Design,
            question: "Should we use approach A or B?".to_string(),
            tried: vec!["Tried A, too slow".to_string()],
            options: vec![
                cowproof_run::escalate::Opt {
                    id: "a".to_string(),
                    summary: "Use approach A with caching".to_string(),
                    cost: "more code".to_string(),
                },
                cowproof_run::escalate::Opt {
                    id: "b".to_string(),
                    summary: "Use approach B".to_string(),
                    cost: "simpler".to_string(),
                },
            ],
            recommend: "a".to_string(),
            blocking: false,
        };
        let _id = q.ask("test-lane", &ask, Origin::Builder).unwrap();
    }

    // Set up the director socket
    let sock_path = control_dir.join("director.sock");
    let listener = director::bind(&sock_path).unwrap();
    let queue_clone = queue.clone();

    let _server = tokio::spawn(async move {
        let _ = director::serve(listener, "test-lane".to_string(), queue_clone, None).await;
    });

    // Give the server a moment to start
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    // Connect and send a rule
    let mut stream = UnixStream::connect(&sock_path).await.unwrap();

    let escalation_id = EscalationId::new("test-lane", 1);
    let request = json!({
        "op": "rule",
        "id": escalation_id.0,
        "verdict": {"answer": "Let's go with approach A"}
    });

    let mut req_bytes = serde_json::to_vec(&request).unwrap();
    req_bytes.push(b'\n');
    stream.write_all(&req_bytes).await.unwrap();

    // Read response
    let mut buf = vec![0u8; 8192];
    let n = stream.read(&mut buf).await.unwrap();
    let response: serde_json::Value = serde_json::from_slice(&buf[..n]).unwrap();

    assert!(response["ok"].as_bool().unwrap());
    assert_eq!(response["outcome"]["id"].as_str().unwrap(), escalation_id.0);

    // Verify the verdict was recorded
    let q = queue.lock().unwrap();
    let (_, _, verdict) = q.get(&escalation_id).unwrap();
    match verdict.unwrap() {
        Verdict::Answer { text } => assert_eq!(text, "Let's go with approach A"),
        _ => panic!("expected Answer verdict"),
    }
}

#[tokio::test]
async fn director_asks_and_rules() {
    test_ask_then_rule().await;
}

#[tokio::test]
async fn director_rejects_unknown_escalation() {
    let tmp = TempDir::new().unwrap();
    let control_dir = tmp.path().join("control");
    fs::create_dir_all(&control_dir).unwrap();

    let queue = Arc::new(Mutex::new(
        Queue::new(&control_dir, Box::new(TestClock)).unwrap(),
    ));

    // Set up the director socket
    let sock_path = control_dir.join("director.sock");
    let listener = director::bind(&sock_path).unwrap();
    let queue_clone = queue.clone();

    let _server = tokio::spawn(async move {
        let _ = director::serve(listener, "test-lane".to_string(), queue_clone, None).await;
    });

    // Give the server a moment to start
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    // Connect and try to rule on a non-existent escalation
    let mut stream = UnixStream::connect(&sock_path).await.unwrap();

    let request = json!({
        "op": "rule",
        "id": "test-lane:E1",
        "verdict": {"answer": "test"}
    });

    let mut req_bytes = serde_json::to_vec(&request).unwrap();
    req_bytes.push(b'\n');
    stream.write_all(&req_bytes).await.unwrap();

    // Read response
    let mut buf = vec![0u8; 8192];
    let n = stream.read(&mut buf).await.unwrap();
    let response: serde_json::Value = serde_json::from_slice(&buf[..n]).unwrap();

    assert!(!response["ok"].as_bool().unwrap());
    assert!(response["error"].as_str().unwrap().contains("unknown"));
}

#[tokio::test]
async fn director_sends_notes() {
    let tmp = TempDir::new().unwrap();
    let control_dir = tmp.path().join("control");
    fs::create_dir_all(&control_dir).unwrap();

    let queue = Arc::new(Mutex::new(
        Queue::new(&control_dir, Box::new(TestClock)).unwrap(),
    ));

    // Set up the director socket
    let sock_path = control_dir.join("director.sock");
    let listener = director::bind(&sock_path).unwrap();
    let queue_clone = queue.clone();

    let _server = tokio::spawn(async move {
        let _ = director::serve(listener, "test-lane".to_string(), queue_clone, None).await;
    });

    // Give the server a moment to start
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    // Connect and send a note
    let mut stream = UnixStream::connect(&sock_path).await.unwrap();

    let request = json!({
        "op": "note",
        "text": "This is a note from the director"
    });

    let mut req_bytes = serde_json::to_vec(&request).unwrap();
    req_bytes.push(b'\n');
    stream.write_all(&req_bytes).await.unwrap();

    // Read response
    let mut buf = vec![0u8; 8192];
    let n = stream.read(&mut buf).await.unwrap();
    let response: serde_json::Value = serde_json::from_slice(&buf[..n]).unwrap();

    assert!(response["ok"].as_bool().unwrap());
    assert!(response["outcome"]["id"].as_str().unwrap().contains("-n"));

    // Verify the note was recorded
    let q = queue.lock().unwrap();
    let notes = q.pending_notes("test-lane");
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].1, "This is a note from the director");
}

#[tokio::test]
async fn director_socket_is_created() {
    let tmp = TempDir::new().unwrap();
    let sock_path = tmp.path().join("director.sock");
    let _listener = director::bind(&sock_path).unwrap();

    let metadata = std::fs::metadata(&sock_path).unwrap();
    // Verify it's a socket
    assert!(metadata.file_type().is_socket());
}

#[tokio::test]
async fn director_rejects_malformed_json() {
    let tmp = TempDir::new().unwrap();
    let control_dir = tmp.path().join("control");
    fs::create_dir_all(&control_dir).unwrap();

    let queue = Arc::new(Mutex::new(
        Queue::new(&control_dir, Box::new(TestClock)).unwrap(),
    ));

    // Set up the director socket
    let sock_path = control_dir.join("director.sock");
    let listener = director::bind(&sock_path).unwrap();
    let queue_clone = queue.clone();

    let _server = tokio::spawn(async move {
        let _ = director::serve(listener, "test-lane".to_string(), queue_clone, None).await;
    });

    // Give the server a moment to start
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    // Connect and send malformed JSON
    let mut stream = UnixStream::connect(&sock_path).await.unwrap();
    stream.write_all(b"not json\n").await.unwrap();

    // Read response
    let mut buf = vec![0u8; 8192];
    let n = stream.read(&mut buf).await.unwrap();
    let response: serde_json::Value = serde_json::from_slice(&buf[..n]).unwrap();

    assert!(!response["ok"].as_bool().unwrap());
    assert!(response["error"].as_str().unwrap().contains("malformed"));

    // Connection should stay open for another request
    stream.write_all(b"still not json\n").await.unwrap();
    let n = stream.read(&mut buf).await.unwrap();
    assert!(n > 0);
}

#[tokio::test]
async fn director_line_cap() {
    let tmp = TempDir::new().unwrap();
    let control_dir = tmp.path().join("control");
    fs::create_dir_all(&control_dir).unwrap();

    let queue = Arc::new(Mutex::new(
        Queue::new(&control_dir, Box::new(TestClock)).unwrap(),
    ));

    // Set up the director socket
    let sock_path = control_dir.join("director.sock");
    let listener = director::bind(&sock_path).unwrap();
    let queue_clone = queue.clone();

    let _server = tokio::spawn(async move {
        let _ = director::serve(listener, "test-lane".to_string(), queue_clone, None).await;
    });

    // Give the server a moment to start
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    // Connect and send a line that exceeds the cap
    let mut stream = UnixStream::connect(&sock_path).await.unwrap();

    // Send a line with "x" repeated more than 64 KiB times
    let oversized = "x".repeat(65 * 1024);
    stream.write_all(oversized.as_bytes()).await.unwrap();
    stream.write_all(b"\n").await.unwrap();

    // Read error response
    let mut buf = vec![0u8; 8192];
    let n = stream.read(&mut buf).await.unwrap();
    let response: serde_json::Value = serde_json::from_slice(&buf[..n]).unwrap();

    assert!(!response["ok"].as_bool().unwrap());
    assert!(response["error"].as_str().unwrap().contains("exceeds"));
}

// CLI binary tests using the real cowproof executable
// Use multi_thread runtime to avoid blocking the director server

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_rule_with_answer() {
    let tmp = TempDir::new().unwrap();
    let lanes_root = tmp.path();
    let lane_id = "test-lane";
    let control_dir = lanes_root.join(lane_id).join("control");
    fs::create_dir_all(&control_dir).unwrap();

    let queue = Arc::new(Mutex::new(
        Queue::new(&control_dir, Box::new(TestClock)).unwrap(),
    ));

    // Create an ask
    {
        let mut q = queue.lock().unwrap();
        let ask = Ask {
            kind: AskKind::Design,
            question: "Test question?".to_string(),
            tried: vec![],
            options: vec![cowproof_run::escalate::Opt {
                id: "a".to_string(),
                summary: "Option A".to_string(),
                cost: "cheap".to_string(),
            }],
            recommend: "a".to_string(),
            blocking: false,
        };
        let _id = q.ask(lane_id, &ask, Origin::Builder).unwrap();
    }

    let director_sock = control_dir.join("director.sock");
    let listener = director::bind(&director_sock).unwrap();
    let queue_clone = queue.clone();

    let _server = tokio::spawn(async move {
        let _ = director::serve(listener, lane_id.to_string(), queue_clone, None).await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cowproof"));
    cmd.arg("rule")
        .arg(lane_id)
        .arg("test-lane:E1")
        .arg("--answer")
        .arg("test answer")
        .arg("--lanes-root")
        .arg(lanes_root);

    let output = tokio::time::timeout(Duration::from_secs(20), cmd.output())
        .await
        .expect("cowproof rule timed out")
        .expect("Failed to run cowproof rule");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify the verdict was recorded
    let q = queue.lock().unwrap();
    let (_, _, verdict) = q.get(&EscalationId::new(lane_id, 1)).unwrap();
    match verdict.unwrap() {
        Verdict::Answer { text } => assert_eq!(text, "test answer"),
        _ => panic!("expected Answer verdict"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_rule_duplicate_rejected() {
    let tmp = TempDir::new().unwrap();
    let lanes_root = tmp.path();
    let lane_id = "test-lane";
    let control_dir = lanes_root.join(lane_id).join("control");
    fs::create_dir_all(&control_dir).unwrap();

    let queue = Arc::new(Mutex::new(
        Queue::new(&control_dir, Box::new(TestClock)).unwrap(),
    ));

    // Create an ask
    {
        let mut q = queue.lock().unwrap();
        let ask = Ask {
            kind: AskKind::Design,
            question: "Test question?".to_string(),
            tried: vec![],
            options: vec![cowproof_run::escalate::Opt {
                id: "a".to_string(),
                summary: "Option A".to_string(),
                cost: "cheap".to_string(),
            }],
            recommend: "a".to_string(),
            blocking: false,
        };
        let _id = q.ask(lane_id, &ask, Origin::Builder).unwrap();
    }

    let director_sock = control_dir.join("director.sock");
    let listener = director::bind(&director_sock).unwrap();
    let queue_clone = queue.clone();

    let _server = tokio::spawn(async move {
        let _ = director::serve(listener, lane_id.to_string(), queue_clone, None).await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // First rule should succeed
    let mut cmd1 = Command::new(env!("CARGO_BIN_EXE_cowproof"));
    cmd1.arg("rule")
        .arg(lane_id)
        .arg("test-lane:E1")
        .arg("--answer")
        .arg("first answer")
        .arg("--lanes-root")
        .arg(lanes_root);

    let output1 = tokio::time::timeout(Duration::from_secs(20), cmd1.output())
        .await
        .expect("cowproof rule timed out")
        .expect("Failed to run cowproof rule");

    assert!(output1.status.success());

    // Second rule on same ID should fail with exit code 1
    let mut cmd2 = Command::new(env!("CARGO_BIN_EXE_cowproof"));
    cmd2.arg("rule")
        .arg(lane_id)
        .arg("test-lane:E1")
        .arg("--answer")
        .arg("second answer")
        .arg("--lanes-root")
        .arg(lanes_root);

    let output2 = tokio::time::timeout(Duration::from_secs(20), cmd2.output())
        .await
        .expect("cowproof rule timed out")
        .expect("Failed to run cowproof rule");

    assert_eq!(output2.status.code(), Some(1));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_note_works() {
    let tmp = TempDir::new().unwrap();
    let lanes_root = tmp.path();
    let lane_id = "test-lane";
    let control_dir = lanes_root.join(lane_id).join("control");
    fs::create_dir_all(&control_dir).unwrap();

    let queue = Arc::new(Mutex::new(
        Queue::new(&control_dir, Box::new(TestClock)).unwrap(),
    ));

    let director_sock = control_dir.join("director.sock");
    let listener = director::bind(&director_sock).unwrap();
    let queue_clone = queue.clone();

    let _server = tokio::spawn(async move {
        let _ = director::serve(listener, lane_id.to_string(), queue_clone, None).await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cowproof"));
    cmd.arg("note")
        .arg(lane_id)
        .arg("test note content")
        .arg("--lanes-root")
        .arg(lanes_root);

    let output = tokio::time::timeout(Duration::from_secs(20), cmd.output())
        .await
        .expect("cowproof note timed out")
        .expect("Failed to run cowproof note");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify the note was recorded
    let q = queue.lock().unwrap();
    let notes = q.pending_notes(lane_id);
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].1, "test note content");
}

#[tokio::test]
async fn cli_lane_not_running() {
    let tmp = TempDir::new().unwrap();
    let lanes_root = tmp.path();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_cowproof"))
        .arg("rule")
        .arg("nonexistent-lane")
        .arg("nonexistent:E1")
        .arg("--answer")
        .arg("test")
        .arg("--lanes-root")
        .arg(lanes_root)
        .output()
        .expect("Failed to run cowproof rule");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not running"));
}
