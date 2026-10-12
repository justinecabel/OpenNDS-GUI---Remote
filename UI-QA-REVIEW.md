# UI experience review — 9 October 2026

Update, 10 October: the settings redesign in AGENTS.md section 42 addresses navigation draft loss, common-editor ordering, specific action names, editor focus after override/profile selection and the Punishment count ambiguity. The visual overhaul in section 43 also adds Clients search/status filters and compact actions through 1300px, plus a consistent shared theme and clearer settings groups. The observations below describe the earlier UI.

All nine live pages were navigated at 1440px and 390px. The desktop links, mobile menu, selected-page indicator, URL fragments, Back/Forward and Escape worked. No page overflow, browser exceptions or API failures were observed during that walkthrough.

Both Classic and Hacker passed the existing 45 interaction checks and the 87-width layout/contrast sweep from 320–2560px, including normal/long content, dialogs and sign-in. All nine desktop page screenshots were also reviewed. These checks pass, but the additional exploratory draft test found a real usability defect that the existing suite does not cover.

**Fix first: unsaved settings disappear on navigation.**

Reproduction: edit a value, visit Portal, then return without saving. The page reloads the saved value without a discard warning. Reproduced with synthetic data and no writes:

| Editor | Saved → draft → value on return | Result |
| --- | --- | --- |
| Limits: Default UL | 5000 → 321 → 5000 | Draft lost |
| SQM: Base ingress | 12500 → 321 → 12500 | Draft lost |
| SQM: WAN-day threshold | 50 → 321 → 50 | Draft lost |
| Punishment: delay | 100 → 321 → 100 | Draft lost |
| Status: configuration | Added a draft comment | Retained |
| Networks: guest behavior | Selected another behavior | Retained |

Recommendation: retain drafts on ordinary page changes, show an “Unsaved” indicator beside the relevant section and reserve discard confirmation for explicit Reload. This can preserve the current navigation behavior. Add regression coverage for navigation away/back and browser history, beyond the existing failed-load/save tests.

**Next: reduce scrolling while preserving the vertical forms.**

The live Limits section measured approximately 2,570px tall on desktop and 2,590px on mobile; SQM measured approximately 1,980–2,000px. Frequent controls take several screens to reach. Put Default and Device before the less frequently used profile editor, collapse optional sections and keep the selected SQM interface visible near both Base and WAN-day controls. Use specific visible button text such as “Save default,” “Save device” and “Apply base queue.”

**Keep the Clients table, but give its data more space.**

At medium desktop widths the pinned rates/actions cover part of the usage area until the administrator scrolls horizontally; this is visible in the 1100px screenshot. The live desktop pinned region measured 567px at 1440px. Retain the table and its existing scrollbar; consider the three-dot action menu at medium widths, plus a search field and Online/Offline filter. Do not bring back the vertical client entries that were reverted.

**Clarify Punishment status.**

The live API reported zero punished devices and active managed traffic control. The page still labels its Devices section “Active,” because the badge reflects shared traffic-control activity, which also includes Limits. Show “0 punished” separately from “Traffic control active,” and link to the relevant filtered devices. The existing API already supplies the punished count.

**Page-by-page suggestions**

| Page | Checked | Suggested improvement |
| --- | --- | --- |
| Overview | Live metrics, graph, range, DNS list/watchlist | Keep the dashboard. Add an explicit stale/connection indicator when sampling stops; the current timestamp requires interpretation. |
| Clients | Interface tabs, table, actions, detail/DNS dialogs, poll focus/scroll | Keep the table; reduce the action footprint at medium widths and add search/state filters. |
| Portal | Design/FAS/upload/download sections and live readiness | When FAS is already Ready, label the disruptive action “Reconfigure gateway” and give it secondary/amber emphasis. Keep its existing restart confirmation. |
| SQM | Per-interface Base/daily grouping, summaries, units, error handling | Preserve drafts, keep the target interface visible and make queue/daily summaries collapsible to shorten the page. |
| Networks | Discovery, unavailable WAN, behavior drafts, mobile navigation | Draft retention works. Mark each changed network, alongside the existing overall “Unsaved network changes” message. |
| Limits | Profiles, Default/Device forms, override selection | Preserve drafts, put common editors first and focus/scroll to Device when an override MAC is selected. Currently selection changes fields above the visible override list without moving focus. |
| Punishment | Form, validation, policy status | Preserve drafts and distinguish the punished-device count from shared traffic-control status. |
| Status & Config | Live summary, Raw, editor, reload/restart controls | Config draft retention works. Add “Unsaved”/“Saved; restart required” state beside the editor so the next action is clear. |
| Logs | Severity colors, long lines, fetch errors, follow-to-end | Keep automatic following enabled as requested. Add an optional Pause/Resume control plus text/severity filters for investigation. |

**Scope and evidence**

- Live browsing allowed only known read endpoints and static assets. No write requests were attempted; no router settings were changed for testing.
- Save/failure/serialization checks used intercepted synthetic APIs. Real FAS reconfiguration, router restarts, archive/upload replacement and client policy mutations were not executed in this review.
- Chromium desktop/mobile emulation was used; this does not establish physical-device or Safari/Firefox coverage.
- Reports: `/tmp/opennds-experience-results/` (`live-navigation.json`, `draft-review.json`, and both themes’ layout/behavior JSON).
- Reviewed synthetic screenshots: `/tmp/opennds-experience-screens/`.

This is a review and recommendation list. Application code, navigation and router policy were left unchanged.
