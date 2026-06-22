---
name: CAL OS admin onboarding journey engine
description: How the admin (business-client) onboarding experience works in index.html — shared state key, home routing, IIFE scoping gotcha, and the same-browser-only live sync limit
---

# Admin onboarding experience (index.html)

Adds a client onboarding journey for the `admin` (business-client) role: a week-by-week
timeline home during onboarding, a celebration on completion, then a maintenance dashboard;
plus an Onboarding sidebar tab (3 phases) where the agency marks steps complete + leaves notes.

## Shared state key — slug of the business name
State lives in localStorage `cal-onboarding-<slug(businessName)>`. The business name is the
agency account's `name` when viewing as agency/test (`accounts[currentAcctId].name`) and
`currentUser.company` when logged in as admin. For Apex Legal both are "Apex Legal Group", so
both roles resolve to `cal-onboarding-apex-legal-group` and share one record.
Shape: `{started, completed, completedAt, steps:{<id>:{done,note,completedAt}}}`. Journey =
`ONB_JOURNEY` (13 steps / phases onboarding|setup|maintenance); only the 10 non-maintenance
steps count toward completion (`ONB_CORE`). Maintenance steps are informational/"Ongoing" — never
checkable, even for the agency.

## IIFE scoping gotcha (important)
index.html has THREE separate IIFEs (`})();` markers). The LAST one (bootFixes, where the
onboarding engine + render*/nav overrides live) has its OWN local copies of
`safeJSON/saveJSON/screen/money/acctKey`, but `slug` and `accountData` are defined only in an
EARLIER IIFE and are NOT in scope there. The engine therefore defines its own local `slug` and
`accountData`. **How to apply:** before calling any helper from new code in the last IIFE, confirm
it's actually defined within that IIFE (grep the line range between its `})();` bounds) — do not
assume top-of-file helpers are visible; redefine or `typeof`-guard if not.

## Home routing
`#home-admin-view` now contains two empty containers — `#home-onboarding-view` and
`#home-maintenance-view` — filled at runtime. `window.applyHomeForRole()` (overridden in the
engine) shows admin-view for `currentRole==='admin'`, then picks timeline vs maintenance by
`onbSyncCompletion().completed`. Completion (all 10 core done) sets `completed=true` and triggers a
one-time celebration overlay (guard key `cal-onb-celebrated-<slug>`). The Onboarding tab screen is
`#s-onboarding`, rendered by `renderOnboardingScreen()` wired in the nav override.

## Live sync is SAME-BROWSER only
Cross-tab live updates use the `window 'storage'` event, which only fires across tabs of the same
browser/origin. There is NO cross-device / cross-browser-context sync (pure localStorage
prototype). The Playwright testing tool's "New Context" gives each context isolated localStorage,
so the agency-completes→admin-sees-flip flow can ONLY be verified within a SINGLE context via
logout/login (doLogout does not clear localStorage). Don't test that flip across separate contexts.

## Plain-English KPI context + milestones
`addKpiContext()` appends a `.kpi-plain` sentence under admin KPI cards matching
`.stat-card, .kpi-card, .cal-kpi` (keyword map → everyday explanation; guarded by `data-kpi-plain`).
Milestone banners (first lead / 10 reviews / first conversion) render in a `#cal-milestone-host`
prepended to `<main>`, only post-completion; dismissals persist in `cal-milestones-<slug>` and
never reshow. **How to apply:** if a new admin screen has KPIs not using those 3 card classes,
extend the `addKpiContext` selector list or req-3 coverage silently drops on that screen.

## Demo seed
`onbSeedDemo()` seeds Apex Legal at 6/10 core steps done (mid-onboarding) so admin lands on the
timeline by default; it no-ops if the key already exists.
