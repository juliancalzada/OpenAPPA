//! Server-side tool identification for OpenCode, the harness integration in
//! `apps/opencode-appa` of the settings checkout.
//!
//! OpenCode's model-visible tool id is a flat string. Host tools keep their
//! name (`bash`, `read`, `edit`, `task`, …); an MCP server's tool is
//! `sanitize(server) + "_" + sanitize(tool)` (OpenCode
//! `packages/opencode/src/mcp/catalog.ts`), which loses the server/tool
//! boundary. The plugin therefore encodes MCP membership in the spelling it
//! sends, exactly as the Claude Code adapter's `mcp__<server>__<tool>` does,
//! and this adapter reads that spelling:
//!
//! | raw spelling | canonical |
//! |---|---|
//! | `execute_remedy_plan` | `appa/execute_remedy_plan`, the runtime's control tool |
//! | `mcp__<server>__<tool>` | `mcp/<server>/<tool>` |
//! | any other `[A-Za-z0-9_.-]+` | `host/opencode/<name>` |
//!
//! `task` is OpenCode's own delegation, but OpenCode exposes no spawn binding
//! or checked child-return lifecycle at the plugin boundary. So this adapter
//! claims no child provenance: `names_children` is empty, no spelling is a
//! spawn, and delegation is an ordinary, explicitly declared call. The `agent`
//! family is not OpenCode's. That limit is reported by the integration, not
//! hidden here.
//!
//! Read right to left the table is partial, exactly as the Claude Code
//! adapter's: the control spelling occupies a cell the `mcp` row would
//! otherwise own, so an ordinary `mcp/appa/execute_remedy_plan` tool has no
//! OpenCode spelling.

use appa_runtime_api::{Adapter, AdapterName, CanonicalTool, IdentifiedTool, ParseRefusal};

/// OpenCode registers the remedy tool as a top-level tool under the runtime's
/// advertised alias; its model calls it by that bare name. Unlike Claude Code,
/// there is no `appa` MCP server, so the `mcp__appa__…` spelling never occurs.
const CONTROL_TOOL_RAW: &str = appa_runtime_api::ADVERTISED_CONTROL_TOOL;
const MCP_PREFIX: &str = "mcp__";

pub fn adapter() -> Adapter {
    Adapter {
        name: AdapterName::Opencode,
        identify_tool,
        // OpenCode assigns a child session id only after the `task` call runs,
        // so a proposed call cannot name its children here. Delegation is an
        // ordinary call; the integration reports that limit.
        names_children: |_, _| Vec::new(),
        spell,
        // No spelling is a spawn, so the wildcard never has one to cover.
        wildcard_covers_spawn: false,
        spells_server: |name| name.starts_with(MCP_PREFIX),
    }
}

fn canonical(raw: &str) -> Result<CanonicalTool, ParseRefusal> {
    let refused = |detail: String| ParseRefusal::Malformed {
        detail: format!("tool {raw:?} is outside the OpenCode adapter's domain: {detail}"),
    };
    // The runtime's own control tool, called by the advertised bare alias.
    if raw == CONTROL_TOOL_RAW {
        return Ok(CanonicalTool::control());
    }
    match raw.strip_prefix(MCP_PREFIX) {
        Some(rest) => match rest.split_once("__") {
            Some((server, tool)) => CanonicalTool::of("mcp", server, tool).map_err(|error| refused(error.to_string())),
            None => Err(refused(format!("{MCP_PREFIX}<server>__<tool> names no tool segment"))),
        },
        None => CanonicalTool::of("host", "opencode", raw).map_err(|error| refused(error.to_string())),
    }
}

fn spell(tool: &CanonicalTool) -> Option<String> {
    if tool.is_control() {
        return Some(CONTROL_TOOL_RAW.to_string());
    }
    let mut segments = tool.as_str().split('/');
    let raw = match (segments.next()?, segments.next()?, segments.next()?) {
        ("mcp", server, name) => format!("{MCP_PREFIX}{server}__{name}"),
        ("host", "opencode", name) => name.to_string(),
        _ => return None,
    };
    (canonical(&raw).as_ref() == Ok(tool)).then_some(raw)
}

fn identify_tool(raw: &str) -> Result<IdentifiedTool, ParseRefusal> {
    Ok(IdentifiedTool {
        canonical: canonical(raw)?,
        // `task` is OpenCode's own delegation, but the plugin boundary exposes
        // no spawn binding or child-return lifecycle, so it is an ordinary
        // call: the runtime does not follow the child and claims no provenance
        // for its return. The integration reports that limit.
        spawn: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_raw_spelling_maps_onto_its_canonical_identity() {
        for (raw, expected) in [
            ("bash", "host/opencode/bash"),
            ("read", "host/opencode/read"),
            ("edit", "host/opencode/edit"),
            ("task", "host/opencode/task"),
            ("mcp__github__create_issue", "mcp/github/create_issue"),
            ("mcp__github__a__b", "mcp/github/a__b"),
            ("mcp__appa__other", "mcp/appa/other"),
            ("mcp__a.b-c__T.o-o_l", "mcp/a.b-c/T.o-o_l"),
            ("mcp_x", "host/opencode/mcp_x"),
            (CONTROL_TOOL_RAW, appa_runtime_api::CONTROL_TOOL),
        ] {
            let canonical = canonical(raw).unwrap_or_else(|refusal| panic!("{raw} maps: {refusal:?}"));
            assert_eq!(canonical.as_str(), expected, "{raw}");
            assert_eq!(canonical.is_control(), raw == CONTROL_TOOL_RAW, "{raw}");
            assert_eq!(
                (adapter().spell)(&canonical).as_deref(),
                Some(raw),
                "the inverse spells {expected} back"
            );
        }
    }

    #[test]
    fn a_canonical_id_outside_the_range_has_no_host_spelling() {
        for name in [
            "agent/kagent/log-analyst",
            "host/claude-code/Bash",
            "host/kagent/memory_persist",
            "host/opencode/mcp__github__x",
        ] {
            let canonical = CanonicalTool::parse(name).expect("the fixture is canonical");
            assert_eq!((adapter().spell)(&canonical), None, "{name}");
        }
        // The ordinary `execute_remedy_plan` tool on an `appa` MCP server is
        // distinct from the control tool and keeps its own spelling.
        let ordinary = CanonicalTool::parse("mcp/appa/execute_remedy_plan").expect("the fixture is canonical");
        assert_eq!(
            (adapter().spell)(&ordinary).as_deref(),
            Some("mcp__appa__execute_remedy_plan")
        );
    }

    #[test]
    fn a_spelling_outside_the_domain_is_a_named_refusal() {
        for raw in [
            "",
            "mcp__",
            "mcp__github",
            "mcp____x",
            "mcp__github__",
            "mcp__git hub__x",
            "mcp__github__x(y)",
            "bash(command:ls)",
            "a/b",
            "host/opencode/bash",
            "agent/kagent/x",
            "appa/execute_remedy_plan",
            "*",
        ] {
            match canonical(raw) {
                Err(ParseRefusal::Malformed { detail }) => {
                    assert!(
                        detail.contains(&format!("{raw:?}")),
                        "the refusal names {raw:?}: {detail}"
                    );
                }
                other => panic!("{raw:?} must be refused, got {other:?}"),
            }
        }
    }

    #[test]
    fn only_the_registered_control_spelling_is_control_and_no_identity_spawns() {
        assert!(identify_tool(CONTROL_TOOL_RAW).unwrap().canonical.is_control());
        for raw in [
            "mcp__appa__other",
            "appa_execute_remedy_plan",
            "mcp__other__execute_remedy_plan",
            // The Claude Code spelling is NOT OpenCode's control tool: here it
            // is an ordinary tool on an `appa` MCP server this harness does not
            // register.
            "mcp__appa__execute_remedy_plan",
        ] {
            assert!(!identify_tool(raw).unwrap().canonical.is_control(), "{raw}");
        }
        // No spelling is a spawn: delegation is an ordinary call at this boundary.
        for raw in ["task", "bash", "mcp__x__y"] {
            assert_eq!(identify_tool(raw).unwrap().spawn, None, "{raw}");
        }
        assert!(!(adapter().wildcard_covers_spawn));
    }

    #[test]
    fn the_adapter_serves_opencode() {
        assert_eq!(adapter().name, AdapterName::Opencode);
    }

    mod laws {
        use super::*;
        use proptest::prelude::*;

        fn segment_chars() -> impl Strategy<Value = String> {
            "[A-Za-z0-9_.-]{0,10}"
        }

        fn raw_spelling() -> impl Strategy<Value = String> {
            prop_oneof![
                segment_chars(),
                (segment_chars(), segment_chars()).prop_map(|(server, tool)| format!("mcp__{server}__{tool}")),
                segment_chars().prop_map(|rest| format!("mcp__{rest}")),
                Just(CONTROL_TOOL_RAW.to_string()),
            ]
        }

        proptest! {
            #[test]
            fn an_accepted_spelling_round_trips_and_is_control_only_when_registered(raw in raw_spelling()) {
                if let Ok(canonical) = canonical(&raw) {
                    prop_assert_eq!(CanonicalTool::parse(canonical.as_str()), Ok(canonical.clone()));
                    prop_assert_eq!(canonical.is_control(), raw == CONTROL_TOOL_RAW);
                    prop_assert!(!canonical.as_str().starts_with("agent/"), "{}", canonical);
                }
            }

            #[test]
            fn the_inverse_spells_every_mapped_identity_back(raw in raw_spelling()) {
                if let Ok(canonical) = canonical(&raw) {
                    let spelled = (adapter().spell)(&canonical);
                    prop_assert_eq!(spelled.as_deref(), Some(raw.as_str()));
                }
            }

            #[test]
            fn an_mcp_server_segment_never_contains_a_double_underscore(server in segment_chars(), tool in segment_chars()) {
                if let Ok(canonical) = canonical(&format!("mcp__{server}__{tool}")) {
                    let namespace = canonical.as_str().split('/').nth(1).expect("a namespace segment");
                    prop_assert!(!namespace.contains("__"), "{}", canonical);
                    prop_assert!(canonical.as_str().starts_with("mcp/"), "{}", canonical);
                }
            }

            #[test]
            fn the_map_is_injective(left in raw_spelling(), right in raw_spelling()) {
                if let (Ok(a), Ok(b)) = (canonical(&left), canonical(&right)) {
                    prop_assert_eq!(a == b, left == right, "{} vs {}", left, right);
                }
            }
        }
    }
}
