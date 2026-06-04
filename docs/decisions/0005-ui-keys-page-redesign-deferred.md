# ADR-0005 — Keys page redesign (deferred pending Level 2 CLI)

**Date:** 2026-06-04  
**Status:** Deferred — resume after Level 2 store CLI is built

---

## Context

The current UI has credential-related UI spread incorrectly across pages:

| Content | Currently in | Should be in |
|---|---|---|
| Biometric sealed secrets list/delete | Settings | Keys page |
| Gate-key management | nowhere yet | Keys page |
| Sealed keys from authority | Devices | Keys page |
| Agent cache/auto-approve | Settings | Settings (stays) |
| Device cert TTL | Settings | Settings (stays) |
| Authority + peer CSR | Devices | Devices (stays) |

## Decision (pending)

The Keys page becomes the single owner of all credential management.  It gets
a **tab bar** inside the page:

```
Keys page
  ├── Tab: Keys          — key list (current content)
  └── Tab: Credentials   — gate-key management + biometric sealed entries
```

The Credentials tab shows:
- Gate-key list (create, verify, change passphrase, revoke) — maps to
  `p43 gate-key` CLI commands
- Biometric sealed entries per key fingerprint (add/remove PIN or passphrase)
  — moves from `_BiometricSecretsSection` in settings_screen.dart

Keys are Level 2 items — their PINs and passphrases live in the Level 2 store,
keyed by `(key_id, fingerprint)`.  The Credentials tab is essentially the UI
for the Level 2 store scoped to keys.

Settings page loses the "Biometric sealed secrets" section entirely.

## Why deferred

The Credentials tab depends on Level 2 store being built.  Without Level 2:
- Gate-key management has nowhere to read/write PINs
- Moving biometric secrets out of Settings would leave a half-finished UI

The correct order:
1. **Level 2 store — CLI** (next up)
2. **Bridge functions** for Level 2 (expose to Flutter)
3. **Keys page Credentials tab** (this ADR)
4. **Settings cleanup** (remove biometric section)

## Files to touch when resumed

- `ui/lib/src/screens/key_list_screen.dart` — add TabBar
- `ui/lib/src/screens/settings_screen.dart` — remove `_BiometricSecretsSection`
- `ui/lib/src/screens/keys/key_detail_sheet.dart` — add per-key credential section
- `bridge/src/api/keys.rs` — add Level 2 bridge functions
- New: `ui/lib/src/screens/keys/credentials_tab.dart`
