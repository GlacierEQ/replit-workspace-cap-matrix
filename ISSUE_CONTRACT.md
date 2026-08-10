# Issue contract — Workspace Cap Matrix

## Problem
Agentic coding workspaces need capability bounds for shell/network/file authority.

## Desired outcome
A bounded, open, testable implementation of **Workspace Cap Matrix** that demonstrates Dispatch workspace actions only through a capability matrix with budget and revoke.

## Non-goals
- Replit affiliation or proprietary integration
- Portfolio-wide scale/performance claims
- UI marketing site

## Acceptance
1. Mechanism module implements allow + refuse with structured receipts
2. pytest behavioral suite green
3. operate.py cold-start produces JSON receipt
4. Non-affiliation disclaimer preserved
