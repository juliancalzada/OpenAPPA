//! The OpenCode adapter end to end: the canonical hook wire (`adapter:
//! "opencode"`) through the served dispatcher, with the tool identification the
//! runtime applies. This is the boundary `opencode-appa` posts to; the plugin's
//! own application of each decision is pinned in its TypeScript suite, which
//! cannot link Rust.
//!
//! These assert the properties the integration must preserve: a call the
//! policy will not release is answered `deny_call` and never `allow_call`; a
//! result the policy will not admit is never `ack`; a remedy offer is
//! executable and, once authorized, the retried call is released; and an
//! unreadable or foreign envelope is refused with a non-2xx status, which the
//! client turns into a thrown error.

mod common;

use std::sync::Arc;

use appa_runtime::api::{RemedyOutcome, Runtime};
use appa_runtime::config::Config;
use appa_runtime_api::{Adapter, AdapterName, DecisionName, PROTOCOL, WireDecision};
use serde_json::json;

/// A runtime whose policy declares one OpenCode host tool, `read`, whose result
/// is confined to the requester. The narrowing is not APPA's to decide alone,
/// so a `read` on a wider trajectory is denied with an offer to accept it. No
/// annotator and no fallback, so every decision is static.
fn deployment(dir: &std::path::Path) -> Arc<Runtime> {
    let path = dir.join("appa.toml");
    std::fs::write(
        &path,
        r#"[policy]
version = 2

[[policy.tool]]
name = "host/opencode/read"
delta = { audience = ["self"] }

[externals]
timeout_ms = 5000
max_body_bytes = 65536
"#,
    )
    .expect("the deployment writes");
    Runtime::open(
        Config::load(&path).expect("the deployment loads"),
        dir.join("appa.db"),
        None,
    )
    .expect("the deployment opens")
    .into()
}

fn adapter() -> Adapter {
    appa_adapter_opencode::adapter()
}

fn wire(event: &str, fields: serde_json::Value) -> Vec<u8> {
    let mut value = json!({ "protocol": PROTOCOL, "adapter": "opencode", "event": event, "root_id": "s1" });
    for (key, field) in fields.as_object().expect("fields is an object") {
        value[key] = field.clone();
    }
    serde_json::to_vec(&value).expect("the event serializes")
}

fn call(tool: &str, arguments: serde_json::Value) -> Vec<u8> {
    wire(
        "tool_call",
        json!({ "tool": tool, "arguments": arguments, "call_id": "call-1" }),
    )
}

fn result(tool: &str, arguments: serde_json::Value) -> Vec<u8> {
    wire(
        "tool_result",
        json!({
            "tool": tool,
            "arguments": arguments,
            "call_id": "call-1",
            "outcome": { "status": "success", "body": "done" },
        }),
    )
}

async fn answer(runtime: &Arc<Runtime>, body: &[u8]) -> (u16, WireDecision) {
    let (status, value) = appa_runtime::hooks::answer(runtime, &adapter(), body).await;
    let decision = serde_json::from_value(value.clone()).expect("the answer is a wire decision");
    (status, decision)
}

/// Only the status of a hook whose body may be the runtime's `{"error": …}`
/// rather than a wire decision.
async fn status(runtime: &Arc<Runtime>, body: &[u8]) -> u16 {
    appa_runtime::hooks::answer(runtime, &adapter(), body).await.0
}

/// A call that would narrow the session is denied with an offer and never
/// released on the first proposal: the plugin throws, so the tool does not run.
#[tokio::test]
async fn a_confining_call_is_denied_never_allowed() {
    let dir = tempfile::tempdir().expect("a temp dir is creatable");
    let runtime = deployment(dir.path());
    assert_eq!(answer(&runtime, &wire("session_start", json!({}))).await.0, 200);

    let (status, reply) = answer(&runtime, &call("read", json!({ "filePath": "secrets/deploy.env" }))).await;
    assert_eq!(status, 200);
    assert!(
        matches!(reply.decision, DecisionName::DenyCall | DecisionName::Block),
        "a call that would narrow is denied, got {:?}",
        reply.decision
    );
    assert!(
        reply.feedback.as_deref().is_some_and(|text| text.contains("offer_id:")) || reply.reason.is_some(),
        "the denial offers a way forward: {reply:?}"
    );
}

/// The remedy handling the integration relies on: the offer the denial names is
/// executable, and the retried call is then released.
#[tokio::test]
async fn the_offered_remedy_releases_the_retried_call() {
    let dir = tempfile::tempdir().expect("a temp dir is creatable");
    let runtime = deployment(dir.path());
    let _ = answer(&runtime, &wire("session_start", json!({}))).await;

    let (_, reply) = answer(&runtime, &call("read", json!({ "filePath": "secrets/deploy.env" }))).await;
    let DecisionName::DenyCall = reply.decision else {
        panic!("the read is denied with feedback, got {:?}", reply.decision);
    };
    let offer = common::last_offer(reply.feedback.as_deref().expect("a denial carries feedback"));
    // The session's own root, under this adapter's prefix: a remedy is spent on
    // the trajectory whose offer it answers.
    let actor = appa_runtime_api::Actor {
        root: appa_runtime_api::TrajectoryId("oc:s1".to_string()),
        child: None,
    };
    assert!(
        matches!(
            runtime.execute_remedy(&actor, offer).await,
            RemedyOutcome::Authorized { .. }
        ),
        "the narrowing offer is executable as offered"
    );

    let (status, retry) = answer(&runtime, &call("read", json!({ "filePath": "secrets/deploy.env" }))).await;
    assert_eq!(status, 200);
    assert_eq!(
        retry.decision,
        DecisionName::AllowCall,
        "the accepted narrowing releases the call"
    );
}

/// A result the policy will not admit is never acknowledged and never
/// delivered: the plugin withholds it from the model.
#[tokio::test]
async fn a_denied_calls_result_is_never_admitted() {
    let dir = tempfile::tempdir().expect("a temp dir is creatable");
    let runtime = deployment(dir.path());
    let _ = answer(&runtime, &wire("session_start", json!({}))).await;
    // The read is denied, so no dispatch is open for its result.
    let _ = answer(&runtime, &call("read", json!({ "filePath": "secrets/deploy.env" }))).await;

    let (status, reply) = answer(&runtime, &result("read", json!({ "filePath": "secrets/deploy.env" }))).await;
    assert_eq!(status, 200);
    assert_ne!(reply.decision, DecisionName::Ack, "the raw result is not admitted");
    assert_ne!(
        reply.decision,
        DecisionName::DeliverValue,
        "the raw bytes are not delivered"
    );
}

/// A tool spelling outside the adapter's domain is malformed and blocks: the
/// runtime never guesses an identity from an encoding it did not send.
#[tokio::test]
async fn a_tool_spelling_outside_the_domain_is_malformed() {
    let dir = tempfile::tempdir().expect("a temp dir is creatable");
    let runtime = deployment(dir.path());
    assert_eq!(answer(&runtime, &wire("session_start", json!({}))).await.0, 200);
    assert_eq!(
        status(&runtime, &call("mcp__github", json!({}))).await,
        409,
        "an incomplete mcp spelling is refused"
    );
}

/// Not JSON, and JSON that is not a wire event, both block before any event
/// exists: a malformed post is never read as an approval.
#[tokio::test]
async fn an_unreadable_hook_is_refused() {
    let dir = tempfile::tempdir().expect("a temp dir is creatable");
    let runtime = deployment(dir.path());
    let (status, _) = appa_runtime::hooks::answer(&runtime, &adapter(), b"{not json").await;
    assert_eq!(status, 400, "not-JSON blocks the action");
    let (status, _) =
        appa_runtime::hooks::answer(&runtime, &adapter(), br#"{"protocol":1,"adapter":"opencode"}"#).await;
    assert_eq!(status, 409, "a wire event missing its event name is malformed");
}

/// A `ruling` asserted under this adapter is refused: OpenCode reviews through
/// the runtime's own elicitation, so no wire envelope could carry a person's
/// answer. A client cannot approve its own blocked call.
#[tokio::test]
async fn a_wire_asserted_ruling_is_refused() {
    let dir = tempfile::tempdir().expect("a temp dir is creatable");
    let runtime = deployment(dir.path());
    let mut body: serde_json::Value =
        serde_json::from_slice(&call("read", json!({ "filePath": "a" }))).expect("the event parses");
    body["ruling"] = json!("approve");
    let (status, _) = appa_runtime::hooks::answer(
        &runtime,
        &adapter(),
        &serde_json::to_vec(&body).expect("the event serializes"),
    )
    .await;
    assert_eq!(status, 409, "a ruling this host never obtained is refused");
}

/// A tool the policy does not name is not released: silence is not approval.
#[tokio::test]
async fn an_undeclared_tool_does_not_run() {
    let dir = tempfile::tempdir().expect("a temp dir is creatable");
    let runtime = deployment(dir.path());
    let _ = answer(&runtime, &wire("session_start", json!({}))).await;
    let (status, reply) = answer(&runtime, &call("bash", json!({ "command": "rm -rf /" }))).await;
    assert!(
        status != 200 || reply.decision != DecisionName::AllowCall,
        "an undeclared tool does not run: status {status}, decision {:?}",
        reply.decision
    );
}

/// An operational fault — here an annotator that does not answer — refuses the
/// hook with a non-2xx status. The plugin turns that into `refuse`, which it
/// raises as an error, so the call does not run and no remedy is offered.
#[cfg(unix)]
#[tokio::test]
async fn an_annotator_that_cannot_answer_refuses_the_hook() {
    let dir = tempfile::tempdir().expect("a temp dir is creatable");
    let script = dir.path().join("classify.sh");
    std::fs::write(&script, "cat > /dev/null\nprintf 'not-json'").expect("the annotator writes");
    let path = dir.path().join("appa.toml");
    std::fs::write(
        &path,
        format!(
            r#"[policy]
version = 2

[[policy.annotator]]
name = "opencode.bash-requirements"
ranks = ["suspicious", "trusted"]
marks = []
effects = []

[[policy.tool]]
name = "host/opencode/bash"
annotator = "opencode.bash-requirements"

[externals]
timeout_ms = 2000
max_body_bytes = 65536

[externals.annotators."opencode.bash-requirements"]
command = ["sh", "{script}"]
"#,
            script = script.display()
        ),
    )
    .expect("the deployment writes");
    let runtime: Arc<Runtime> = Runtime::open(
        Config::load(&path).expect("the deployment loads"),
        dir.path().join("appa.db"),
        None,
    )
    .expect("the deployment opens")
    .into();

    let _ = answer(&runtime, &wire("session_start", json!({}))).await;
    let status = status(&runtime, &call("bash", json!({ "command": "ls" }))).await;
    assert_eq!(status, 409, "a fault fails the call closed rather than running it");
}

/// The adapter serves under its own name; a wire event carrying another
/// adapter is refused.
#[tokio::test]
async fn an_event_for_another_adapter_is_refused() {
    let dir = tempfile::tempdir().expect("a temp dir is creatable");
    let runtime = deployment(dir.path());
    let mut body: serde_json::Value =
        serde_json::from_slice(&wire("session_start", json!({}))).expect("the event parses");
    body["adapter"] = json!("claude-code");
    let (status, _) = appa_runtime::hooks::answer(
        &runtime,
        &adapter(),
        &serde_json::to_vec(&body).expect("the event serializes"),
    )
    .await;
    assert_eq!(status, 409, "an event for another adapter is refused");
    assert_eq!(adapter().name, AdapterName::Opencode);
}
