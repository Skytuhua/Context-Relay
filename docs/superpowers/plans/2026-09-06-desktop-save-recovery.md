# Desktop Save Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Preserve and explicitly recover submitted, unconfirmed desktop changes after restart.

**Architecture:** Desktop prepares a typed request in the encrypted vault, sends the original mutation, and removes its recovery copy only after a usable acknowledgment. Home reads paginated recovery summaries and offers explicit review, retry and dismissal.

**Tech Stack:** Rust, SQLCipher/rusqlite, local authenticated IPC, generated TypeScript/JSON Schema, React/Vitest.

**Spec:** ../specs/2026-09-06-desktop-save-recovery.md

## Global Constraints

Preserve user records and existing dirty untracked tooling. Do not operate the installed app, native harness settings, credentials or normal daemon. No automatic mutation retry, plaintext draft storage, new signing service or production compatibility claims from fixture tests.

## Tasks

- [x] Add protocol DesktopWrite enum, prepare/list/get/forget requests and results, strict validation and bounded summaries. Update exports and protocol version/authentication/shutdown compatibility fixtures.
- [x] Add migration 26 and focused vault journal module with exact payload binding, capacity checks, cursor listing and explicit removal. Verify encrypted reopen, altered-ID rejection and no mutation during prepare.
- [x] Wire Desktop-only daemon routes and test access controls and isolated prepare/restart/replay behavior.
- [x] Prepare gateway writes durably, retain IDs on uncertainty, treat cleanup failure separately from known save success, and implement explicit recovery methods.
- [x] Add an accessible Home recovery panel with review, retry and dismissal text. Verify restart, wrong acknowledgments, no startup writes, retry replay and failure retention.
- [x] Run relevant Rust/frontend/contract checks, independent review, graphify update, verification notes and commit/push the verified change; report remaining release limitations.
