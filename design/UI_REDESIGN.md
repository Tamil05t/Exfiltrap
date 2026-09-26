# ExfilTrap Console — UI Redesign Spec

Status: authoritative spec for the `exfiltrap/dashboard/templates/index.html` rewrite.
Source: UI-designer brief, reconciled against the real API surface in
`exfiltrap/dashboard/app.py` and `exfiltrap/storage.py`. No field is rendered that
the API does not actually return.

## 1. Why the current UI fails

- Seven flat tabs with no hierarchy: Overview / Live Queries / Alerts / Sessions /
  Responses / Canary / Service all sit at the same level, so the operator must know
  which tab owns which question.
- Views are toggled with `display:none` + `.active`, so every view's DOM exists at all
  times and hidden views still get refreshed/queried.
- Severity is communicated by **color alone** (`.pill.HIGH` vs `.pill.CONFIRMED` look
  structurally identical), which fails for color-blind operators and in screenshots.
- Inline `onclick="unblock('...')"` string-interpolated handlers — fragile on names
  containing quotes, untestable, and a blacklist item.
- Native `confirm()` for the destructive sink purge.
- No global search, no sortable columns, no time range, no drill-down from a row to its
  source, no "X new since you looked" affordance — the live feed either yanks scroll or
  is stale.
- Table rows are unvirtualized and the whole table re-renders on every tick.
- No first-class empty / error / degraded states — a dead engine looks like a slow one.

## 2. Information architecture

Four destinations, organized by the operator's actual questions:

| Destination | Question it answers | Absorbs |
|---|---|---|
| **Overview** | "Is anything wrong right now?" | old Overview |
| **Triage** | "What exactly happened, and from whom?" | Live Queries + Alerts + Sessions |
| **Response** | "What did we do about it?" | Responses + Canary + allowlist + mute |
| **System** | "Is the sensor itself healthy?" | Service & Health |

Triage has two **modes** (not tabs at the nav level): `Events` and `Sources`.
Response has two modes: `Ledger` and `Traps & Policy`.

An always-visible **StatusBar** spans the top: it carries capture health, mode, uptime,
query count, and the SSE state — so those facts are never hidden behind a tab.

## 3. Routing

Hash routing: `#/overview`, `#/triage/events`, `#/triage/sources`, `#/response/ledger`,
`#/response/policy`, `#/system`.

- `hashchange` drives the router; nav clicks set `location.hash` (no inline handlers).
- The router shows exactly one view element by toggling a single `.is-active` class on
  `.view` containers; CSS hides the rest. Only the active view is refreshed.
- Deep-linking a query/source opens the detail drawer: `#/triage/events?sel=<key>`.

## 4. Risk visual language (fixes color-only severity)

Severity must be triple-encoded: **color + shape + label**.

| Level | Color token | Shape | Fill |
|---|---|---|---|
| LOW | `--lvl-low` (slate) | circle | hollow |
| MEDIUM | `--lvl-med` (amber) | square | hollow |
| HIGH | `--lvl-high` (orange-red) | triangle | outlined |
| CONFIRMED | `--lvl-conf` (red) | **hexagon** | **solid** |

The `RiskBadge` component renders `<span class="risk risk-HIGH">` with a CSS-drawn SVG or
clip-path glyph plus the text label. CONFIRMED rows also get a left **severity rail**
(4px solid bar) so the distinction survives grayscale.

## 5. Layout

```
┌──────────────────────────────────────────────────────────────────────┐
│ STATUS BAR  ● capture ok │ mode live:wlo1 │ ↑4h12m │ 128,402 q │ SSE LIVE │
├──────────┬───────────────────────────────────────────────────────────┤
│          │  POSTURE BANNER (only when degraded / under attack)       │
│  NAV     │ ┌───────────────────────────────────────────────────────┐ │
│  RAIL    │ │ view content (routed)                                 │ │
│  ──────  │ │                                                       │ │
│ Overview │ │                                                       │ │
│ Triage 4 │ │                                                       │ │
│ Response │ │                                                       │ │
│ System   │ │                                                       │ │
│          │ └───────────────────────────────────────────────────────┘ │
│ ──────   │                                                           │
│ engine   │                                                           │
│ card     │                                                           │
├──────────┴───────────────────────────────────────────────────────────┤
│ FOOTER TICKER: capture · last alert · sinks · version                │
└──────────────────────────────────────────────────────────────────────┘
```

Nav rail count badges are live: Triage shows open HIGH+CONFIRMED, Response shows
active ledger entries.

## 6. Components (all vanilla JS, no framework)

| Component | Responsibility |
|---|---|
| `StatusBar` | capture health dot, mode, uptime, query total, SSE state chip |
| `NavRail` | 4 destinations + counts + engine summary card |
| `PostureBanner` | verdict-driven banner: hidden when calm, amber when elevated, red when CONFIRMED present or capture degraded |
| `StatCard` | label, value, delta, sub-note, sparkline slot |
| `LiveFeedTable` | sortable, pausable, flash-on-insert, virtual-lite (caps rows) |
| `NewItemsBar` | "N new events — click to show" sticky bar; never yanks scroll |
| `FilterBar` | text search, risk multi-select, process/resolver filter, time range |
| `DetailDrawer` | right-side slide-over: full evidence for one event/source |
| `ConfirmDialog` | replaces native `confirm()` for destructive actions |
| `ToastStack` | transient success/error notices |
| `CommandPalette` | Cmd/K opens; jump to views, search qnames/sources, run actions |
| `RiskBadge` / `SeverityRail` | severity triple-encoding |
| `MonoCell` / `QnameCell` | monospace, tabular numerals, truncate + title, click-to-copy |
| `ReasonsChips` | parse `reasons` into signal chips + MITRE tags |
| `EmptyState` / `ErrorState` | explicit "quiet", "standalone", "engine down", "load failed" |

## 7. Live-data strategy (SSE + polls, never yanking)

- `/api/stream` (SSE, ~1s) feeds new queries + events into an in-memory buffer.
- If the tracer is scrolled to top and not paused, new rows prepend immediately.
- If the operator scrolled away or hovered, buffer instead and show `NewItemsBar`.
- `/api/stats` polled at **5s** (server has a 2s cache), `/api/status` at **10s**.
- Pause button freezes both SSE application and polling; resume flushes the buffer.
- `document.hidden` suppresses polling; on focus, one immediate refresh.

## 8. Typography & density

- Data (IPs, qnames, hashes, timestamps): `--mono` with `font-variant-numeric: tabular-nums`.
- UI labels: `--sans`, 10–11px uppercase w/ letter-spacing for section heads.
- Row height 34px; 13px base; comfortable 44px medium density selector.
- Timestamps render as `HH:MM:SS` relative-friendly (today) or `MM-DD HH:MM` older.

## 9. States

- **Empty**: "no flagged traffic yet — quiet network" with a muted glyph.
- **Standalone** (no engine attached, `/api/status` has no `mode`): whole console
  switches to a read-only-DB posture; capture card says STANDALONE, live views still
  render historical rows.
- **Degraded**: `capture_healthy === false` or heartbeat age high → PostureBanner red,
  StatusBar dot warn.
- **Error**: any fetch that fails renders an `ErrorState` with retry, never a blank card.

## 10. Anti-patterns (must not appear in the rewrite)

1. `display:none` toggling of always-present views → use one `.is-active`.
2. Inline `onclick="..."` string handlers → `addEventListener` + delegation + `data-*`.
3. Native `confirm()` / `alert()` → `ConfirmDialog` / `ToastStack`.
4. Emoji as iconography → inline SVG glyphs.
5. Color-only severity → color + shape + label.
6. Refreshing hidden views.
7. Re-rendering the whole table on every SSE tick.
8. Scroll position jumps when new rows arrive.
9. Global mutable state without a single source of truth.
10. Silent fetch failures → ErrorState + toast.

## 11. Feature additions (ranked by value/effort)

1. Global search / command palette (Cmd+K).
2. Sortable everything + column persistence.
3. Detail drawer with decoded payload, ATT&CK, reasons, copyable evidence.
4. Time-range selector on Overview charts (5m/30m/2h/24h).
5. Source drill-down: click a src_ip → all its queries/events/sessions.
6. Pause-on-hover live feed + "N new" bar.
7. Export evidence pack with the selected window.
8. Keyboard nav (j/k rows, Enter opens drawer, Esc closes).
9. Density toggle (comfortable/compact).
10. Relative timestamps + absolute on hover.

## 12. API contract (do not invent fields)

- `GET /api/stats` → `{totals:{queries,flagged,confirmed,blocked,sinkhole_hits},
  levels:{LEVEL:n}, response_flags, timeseries:[{bucket,queries,flagged}],
  top_sources:[{src_ip,flagged,total}], top_domains:[{domain,flagged}]}`
  (app.py renames storage `top_flagged_domains` → `top_domains` on this route.)
- `GET /api/status` → `{mode,uptime_s,queries_processed,can_capture,can_firewall,
  is_root,capture_healthy,capture_heartbeat_age_s,capture_ifaces,api_port,db_path,
  blocked_count, privileges:{is_root,cap_net_raw}, policy:{sinkhole,sinkhole_strikes,
  sinkhole_ttl,popularity_guard,self_dos_guard,own_ips}, canaries:[...],
  sinkhole_domains:[...], notify_socket}` or `{service:"standalone-dashboard"}`.
- `GET /api/queries?limit&risk` → `{queries:[{ts,src_ip,qname,risk_level,
  rf_probability,resolver,process}]}`
- `GET /api/events?limit` → `{events:[{ts,src_ip,qname,risk_level,reasons,confirmed,
  decoded_preview,resolver,process,mitre}]}`
- `GET /api/blocked` → `{blocked:[{target,ts,risk_level,kind,trigger_src,qname,
  resolver,process,details}]}`
- `POST /api/unblock {src_ip}` — note: current UI posts `{target}`; verify server reads.
- `GET/POST/DELETE /api/allowlist` → `{allowlist:[{ip,ts,note}]}`; body `{ip,note?}`
- `GET/POST/DELETE /api/mute` → `{muted:[{domain,ts,note}]}`; body `{domain,note?}`
- `GET /api/sinkhole` → `{domains:[...],hits:[{ts,qname,base}|{total}],enabled}`
- `DELETE /api/sinkhole` clears
- `GET /api/stream` — SSE
- `GET /api/export?window=N` — evidence JSON
- `GET /api/sessions` → `{sessions:[{src_ip,query_count,mean_mass,cumulative_mass,
  interval_cv,last_seen,slow_drip,beacon,velocity,domain_beacon,resp_answer_bytes}]}`

## 13. Compatibility constraints

- `tests/test_service.py::test_ui_renders` asserts the `/` response contains the bytes
  `ExfilTrap`, `view-overview`, and `api/stream`. The rewrite MUST keep all three
  (brand string, a `view-overview` element id/class, and the SSE endpoint literal).
- Tauri's `frontendDist` is `exfiltrap/dashboard/templates` — keep `index.html` and
  `waiting.html` at those paths.
- No external build step; single self-contained HTML file is acceptable and preferred.

## 14. Implementation order

1. Shell: tokens, app grid, StatusBar, NavRail, router, toasts, palette skeleton.
2. Overview: posture banner, stat cards, charts, top talkers, mini feed.
3. Triage: feed table, filters, drawer, SSE buffer + new-items bar.
4. Response: ledger, traps/policy, allowlist/mute, confirm dialog.
5. System: capture, engine, policy, export.
6. States pass: empty/error/standalone/degraded on every view.
7. Verify: pytest, endpoint coverage, manual degraded simulation.
