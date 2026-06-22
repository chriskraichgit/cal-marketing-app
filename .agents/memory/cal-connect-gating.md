---
name: CAL OS connect-gating for data dashboards
description: Convention for showing "Connect Platform" empty-states instead of fake analytics on dashboard screens.
---

# Connect-gating convention

Data/analytics dashboard screens (Analytics, Campaigns, ROI, Revenue, SEO, Social) must NOT show hardcoded fake numbers by default. They show a "Connect Platform" gate until the relevant integration is connected — mirroring the SEO screen (`#s-seo`).

**How to apply (when adding/converting a dashboard):**
- Add a gate card as a **direct child** of the screen `<div>`, placed immediately after the `.sec-head` (e.g. `#roi-gate`, `#campaigns-gate`, `#revenue-gate`). It must be a balanced, self-contained `card card-pad` with connect buttons calling `openOAuthModal('<platform>')`.
- Gating is done by `gateDataScreen(screenId, gateId, keys)`: it hides every direct child except `.sec-head` and the gate when not connected, and hides the gate when connected. Add a thin wrapper (e.g. `gateRoi()`) and include it in `gateAllDataScreens()`.
- Wire the wrapper into THREE places: the `window.nav` wrapper, the account-refresh hook (`window.currentScreen===...`), and the oauth-success handler (via `gateAllDataScreens()`).
- `keys` are the lowercased, space-stripped platform names as stored by the oauth handler in `localStorage['cal-integrations-'+acctId]` — e.g. Google Ads → `googleads`, Meta Ads → `metaads`, Stripe → `stripe`, GBP → `gbp`.

**Why:** Client wants real-data-or-nothing — no fake analytics. The gate card being a direct child is required because `gateDataScreen` iterates `screen.children`; nesting it deeper breaks the show/hide. Also see cal-os-structure.md: an unclosed div makes later screens render blank.
