# UI QA — 8 October 2026

All nine manager pages and sign-in were checked with Chromium using synthetic data. Every browser API request was intercepted, including writes; router settings were never changed by these checks.

| Coverage | Result |
| --- | --- |
| 87 widths, 320–2560px: 32px steps plus exact layout breakpoints | Pass: 1,566 page/width checks across normal and long-name data |
| Domain/client dialogs at 12 widths; desktop and mobile table scrolling | Pass: contained content, accessible actions, solid dock backgrounds |
| Empty/error states on all nine pages at 10 widths | Pass: no page overflow or browser exceptions |
| Initial loading at 320, 390, 768, and 1440px | Pass: Limits saves wait for loaded data |
| Touch emulation and 568×320 landscape navigation | Pass: navigation, table actions, dialog close, SQM controls |
| Text contrast on visible, enabled text | Pass: no flagged pairs in the normal-data audit |
| 16 saved behavioral regressions | Pass: focus, delayed responses, failed loads/saves, serialization, range/unit persistence, MAC validation |
| Navigation, keyboard, Escape, back/forward, old links, Config drafts | Pass |
| Watchlist, portal preview/apply/FAS/archive/upload/download, profiles, overrides, daily SQM, restart | Pass with mocked mutations |
| Existing five browser-history regression checks | Pass |

Screenshots were visually reviewed at phone, tablet, and desktop sizes, including long domains/hostnames and settings sections.

## Repairs

- Removed the 480px mobile SQM heading gap and aligned controls within each field row. Page headings keep their action alongside the title on phones.
- Contained long domains/hostnames in watchlists, tables, dialogs, and result messages. Charts now render at their actual displayed width instead of shrinking a minimum 320px drawing.
- Improved link and offline dock-text contrast.
- Preserved keyboard focus during Client refreshes and restored it after closing a client dialog. DNS detail remains open and updates during ranking refreshes.
- Replaced the timed Client-to-Limits handoff with an awaited load. Empty/invalid Device MACs cannot submit Default.
- Failed Limits/SQM loads and saves retain drafts and show diagnostic errors. Actions wait for the initial load; pending saves disable controls and submit once. Empty Clients has a visible state.

## Deployment

Rebuilt with `docker compose up -d --build`. Authenticated GET checks passed for the UI, sign-in, all four stylesheets, and all 13 page API endpoints. Served markup/CSS match the workspace.

## Repeat

The app remains Flask + vanilla JS. Playwright and Chromium are external, optional QA tools.

From the project directory, with those tools installed outside the workspace:

```sh
PLAYWRIGHT_MODULE=/tmp/node_modules/playwright CHROMIUM_PATH=/usr/bin/chromium node tests/ui_qa.cjs
```

Use `--layout-only` or `--behavior-only` for a focused run. Artifacts default to `/tmp/opennds-ui-qa`; `UI_QA_OUTPUT` overrides the directory. This run's artifacts are `/tmp/opennds-qa-final`.

This covers sampled widths and Chromium emulation. Physical iOS/Android devices and other browser engines were not verified. Mocked action checks verify UI requests and behavior, not router-side execution.

## Classic / Hacker themes

Both skins passed the 87-width layout/contrast sweep, all nine pages with normal and long-name data, the 16 behavior checks, and desktop/mobile navigation tests. Theme-specific browser checks passed for pre-paint restore, refresh/sign-in persistence, cross-tab synchronization, Config/login draft preservation, chart colours/ranges, and unavailable or invalid storage. The Hacker chart reserves room for monospace axis labels. `tests/test_themes.cjs` provides dependency-free preference regressions. Theme browser checks used mocked APIs and made no writes. Artifacts: `/tmp/opennds-theme-classic` and `/tmp/opennds-theme-hacker`.

## DNS watchlist dialog

Moved watchlist add/remove controls into a native dialog and expanded the Overview DNS ranking to the full width. Both themes passed the 87-width Overview sweep, dialog geometry at 12 widths, and visible-text contrast checks. All 21 behavior checks passed, including watchlist Enter/add/remove, failed saves preserving drafts, serialized saves, empty/50-domain lists, focus during refresh, Escape/backdrop return focus, and clicking dialog padding. All mutations were mocked. Screenshots were visually reviewed at mobile and desktop widths. Rebuilt the container; served markup/CSS and read-only DNS/Overview/Clients APIs passed live checks. Artifacts: `/tmp/opennds-watch-classic` and `/tmp/opennds-watch-hacker`.
