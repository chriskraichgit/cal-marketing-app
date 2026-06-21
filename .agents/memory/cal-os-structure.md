---
name: CAL OS single-file app structure
description: Layout/rendering pitfalls in index.html (single-file portal) — screen nesting, the replaceScreens override layer, and blank-screen root cause
---

# CAL OS (index.html) screen rendering

Single-file HTML portal (~6200+ lines) served by server.js on port 5000. Roles: agency, admin, user, test.

## Screens must be direct children of `<main class="main">`
Every page is a `<div class="screen" id="s-xxx">`. CSS: `.screen{display:none}` / `.screen.active{display:block; min-height:calc(100vh-104px)}`.

**Rule:** a screen renders only if it is a *direct sibling* of the other screens inside `<main class="main">`. If a screen's markup has an unclosed `<div>`, every following screen nests inside it; since the parent screen is `display:none` when inactive, the nested screens render at `offsetHeight=0` (look blank) even though `.active` and full content are present.

**Why:** this caused ~10 pages (social, leaderboard, whitelabel, invoicing, proposals, nps, referrals, job-logging, booking, revenue) to appear blank for BOTH roles. Two screens each had one missing `</div>`. The missing close was *inside* a screen (e.g. between two tab panels), so the screen's own closing comment closed an inner div instead — the comment lied about what it closed.

**How to apply:** to find these, parse the body (everything before the first `<script>`), split on `<div class="screen" id="s-`, and for each segment count `<div\b` vs `</div>` — every screen segment must net to 0. Also verify tab-panel siblings the same way (e.g. `sales-tab-panel-dashboard` must net 0 before `sales-tab-panel-training` opens, or Training nests in Dashboard and tab-switching breaks). When fixing, place the added `</div>` at the correct nesting level, not just before the next screen.

## The `replaceScreens()` override layer
`replaceScreens()` (called by `bootFixes()` on DOMContentLoaded and on launchApp) uses `setHtml(...)` to OVERWRITE several static screens at runtime (help, plans, billing, nps, referrals, proposals, job-logging, whitelabel — and formerly social). This silently clobbers richer static HTML.

**Why/How:** if a static screen looks wrong/old at runtime but correct in the source, check whether `replaceScreens()` overwrites it. The newer 7-platform Social hub was being replaced by an old 3-platform version until the `setHtml('s-social',...)` line was removed.

## Testing harness note
The Playwright testing skill caps at ~10 iterations per run and the admin onboarding modal + login consume several. Keep test plans tiny (1–2 navigations). Prefer in-page `eval` returning a single diagnostic string (offsetHeight, parent id, closest('.main')) over visual judgment — the agent's visual "blank" reports were unreliable; geometry probes found the truth.
