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

## Per-account branding must NOT override `--gold`
`applyAccountBranding()` themes the dashboard per selected account. It must keep the brand `--gold` CSS var fixed (#c9a84c) and store the account's brand color in a SEPARATE var (`--acct`).

**Why:** buttons (`.btn-connect`, `.ob-btn`, `.btn-primary`) are gold background + black text. Earlier the function did `setProperty('--gold', account.color)`; accounts like Apex Legal are navy (#1b3a6b), so every gold button became navy with unreadable black text. This was the user-reported "blue and black button" bug.

**How to apply:** if buttons appear the wrong color per-account, check what `applyAccountBranding()` (in the window.* override block) sets on `--gold`.

## Profile photo: inline cssText must include `display:block`
CSS has `.profile-avatar-circle img{display:none}` by default. When applying a profile photo via `element.style.cssText='...'`, the string must include `display:block`, otherwise the stylesheet's `display:none` wins and the photo stays hidden — even though the top-right `.avatar-btn img` (no display:none) shows fine. Applies in both `handleProfilePhoto` and the launchApp photo-restore block.

## Duplicate function definitions — edit the WINNING one
Many functions exist twice: a static `function foo()` AND a later `window.foo = function(){...}` in the fix/boot block. The window override wins. Always edit the later/window version (e.g. setCurrentAcct, nav, refreshScreenForAccount, OB_STEPS, applyAccountBranding).

## Fixed-screen routing (`FIXED_SCREEN_SET`)
`FIXED_SCREEN_SET={help,plans,billing,whitelabel}`. The active `nav()` wrapper early-returns into `renderFixedScreen(id)` for these ids — so hooks placed only after `priorNav(id)` in the nav wrapper will NOT run for them. To run per-screen logic for a fixed screen (e.g. role-aware `renderBilling()`), add the call inside `renderFixedScreen()`.

## Connector connection state
Connections are stored per account in localStorage key `cal-integrations-<acctId>` as `{platformKey:true}`, where platformKey = OAUTH_DATA[platform].name lowercased with spaces stripped (e.g. 'googleads','metaads','googlebusinessprofile','stripe'). Written by `completeOAuth()`. Analytics/billing gating reads these keys.

## Role-aware screen pattern (Team screen)
The Team screen (`s-team`) shows different content per role by wrapping each variant in its own div (`#team-agency-view` hidden by default, `#team-client-view`) and toggling them in `renderTeam()` on `currentRole` (agency/test vs admin). `renderTeam()` is wired in the nav wrapper for `id==='team'` (team is NOT in FIXED_SCREEN_SET). Agency view has Agency Members + Client Admins tabs; invites persist to localStorage `cal-agency-invites` / `cal-admin-invites` and re-render. Use this same wrap-and-toggle pattern for any other role-divergent screen. Always HTML-escape user-entered invite values before `innerHTML` (helper `teamEsc`).

## Account switcher already exists
Agencies already have a top-left account dropdown (`#acct-switcher-wrap` / `#acct-sw-btn`, list `#acct-dd-list`, built by `buildAcctDd()`, shown for agency/test in setupRoleUI) with "New Account". Don't rebuild it — it lets the agency switch/manage all client accounts (a1–a5). Agency members are seeded in `AGENCY_USERS` (chris/james/matt @cal.marketing).

## Role logins
Agency=chris@cal.marketing (CAL Marketing, skips onboarding, sees all client accounts a1–a5 + can create). Admin=client@apexlegal.com. User=staff@apexlegal.com. Test role also exists. Agency/test get the account switcher; agency routed straight to launchApp (no business-account onboarding).

## getMeta() only fills defaults when the account key is entirely absent
`getMeta(key)` (in the window.* boot block) lazily seeds full defaults (name/initials/plan/color/logo/font/language) only when `!all[key]`. So any code that pre-writes a PARTIAL `cal-account-meta[id]` (e.g. just `{location}`) permanently blocks default seeding — downstream readers like `refreshScreenForAccount` (`m.name`) then get undefined and show generic/blank labels.

**Why:** `createAccount()` writing `{location}` alone left new accounts with no name/color in meta.

**How to apply:** when writing meta for a not-yet-seeded account, write a COMPLETE object (all default keys + your field), not a partial patch. Inside the boot closure use `saveMeta()`; from static functions (like `createAccount`, which is NOT window-overridden) merge full defaults manually.

## Admin nav simplification — sidebar visibility has THREE layers
Sidebar `.nav-btn` visibility is permission-driven: `setupRoleUI` shows a button only if its `nav('x')` target is in `getPermissions(role,email)` (default = `DEFAULT_PERMISSIONS[role]`, overridable per-email via `agencyPermissions`/`cal-agency-perms`). To trim a role's nav, edit `DEFAULT_PERMISSIONS[role]` — BUT two later layers can re-inflate it:
1. `ensureScreensAndNav()` (boot block) force-PUSHES `['leaderboard','job-logging','social','nps','referrals']` back into role perm arrays at runtime and filters per-role. Exclude the role from the push + add to its filter, or trimmed perms get undone.
2. `cleanAdminNav()` force-sets specific buttons (job-logging, leaderboard, proposals) `display` per role AFTER the perm loop — it can re-show buttons the perm loop hid. Set them to `'none'` for the role.

**Static section labels** (Overview/Marketing/Work/Files & Billing/Settings) always render; only `nav-label-sales`/`nav-label-admin` are id'd + conditionally hidden. After trimming, ensure each visible section still has ≥1 item, and hide `nav-label-admin` for admin (else orphan header).

**Why:** request to make the admin (business client) home/nav "less busy for marketing" — admin trimmed to `['home','campaigns','reviews','leads','inbox','files','billing','reports','settings','profile','help']`. `nav()` itself ignores permissions, so home CTAs to non-sidebar screens still work.

## Admin home is role-toggled (simplified view)
`#s-home` holds two siblings: `#home-admin-view` (CTA-first: "Where Your Money Is Going" spend breakdown + Quick Action `.admin-cta` cards + compact health score) and `#home-full-view` (original busy hero/KPI/health grids). `window.applyHomeForRole()` shows admin-view only when `currentRole==='admin'`, else full-view. Wired in `setupRoleUI`, the `nav()` wrapper (`s==='home'`), and `refreshScreenForAccount` (keeps `#admin-health-score` mirrored from `#h-score`).

## Testing harness note
The Playwright testing skill caps at ~10 iterations per run and the admin onboarding modal + login consume several. Keep test plans tiny (1–2 navigations). Prefer in-page `eval` returning a single diagnostic string (offsetHeight, parent id, closest('.main')) over visual judgment — the agent's visual "blank" reports were unreliable; geometry probes found the truth.

## Shared #nav-label-admin section header (per-role text)
`#nav-label-admin` is ONE shared sidebar section header. setupRoleUI toggles both its
visibility AND its text per role: admin sees it as "Feedback" (now contains only the
Satisfaction/`nps` item), agency/test see it as "Admin". If you hide it for admin again,
the lone Satisfaction button floats headerless. Admin Satisfaction visibility needs THREE
things in sync: `nps` in DEFAULT_PERMISSIONS.admin, `nps` NOT in the ensureScreensAndNav
admin filter list, and the label shown.

## New self-signup accounts -> agency switcher
submitCreateAccount() must push a new account into localStorage `cal-accounts` (+ complete
`cal-account-meta` entry) for it to appear in the agency account switcher (buildAcctDd reads
cal-accounts). finishOnboarding() does NOT create accounts, so there's no duplicate.

## Profile photo lives on two circles
Profile photo (saveState 'profilePhoto') must be applied to BOTH `#profile-avatar-circle`
(Profile page) and `#settings-pfp-preview` (Settings card), plus topbar `#avatar-btn`.
handleProfilePhoto + launchApp restore loop both circle ids; fillSettingsPfp() (called on
nav to settings) rehydrates the settings preview. Inline img cssText MUST include
display:block (CSS default for .profile-avatar-circle img is display:none).
