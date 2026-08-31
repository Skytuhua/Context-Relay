---
type: "query"
date: "2026-08-31T10:53:45.166392+00:00"
question: "Windows 64-call cancellation and ACL fixture failure boundaries"
contributor: "graphify"
outcome: "useful"
source_nodes: ["sixty_four_real_calls_and_cancellations_fit_below_the_daemon_cap()", "pipe_security_descriptor()"]
---

# Q: Windows 64-call cancellation and ACL fixture failure boundaries

## Answer

Expanded against graph vocabulary: sixty four calls cancel pipe windows descriptor security. The graph identifies the real 64-call end-to-end test, dispatcher cancellation tests, and Windows pipe ACL test as navigation anchors. Direct source and CI at89d832b separately established one-shot pipe busy failure, unbounded test gate, raw Windows TOML fixture paths, and missing READ_CONTROL only in the native ACL inspection fixture. Fix commit435367d has166 targeted local cases passing; actual clean Windows runtime is pending. Graph edges alone do not prove these defects.

## Outcome

- Signal: useful

## Source Nodes

- sixty_four_real_calls_and_cancellations_fit_below_the_daemon_cap()
- pipe_security_descriptor()
