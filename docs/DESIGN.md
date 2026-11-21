# Design system

The console's visual language is **Harbor**: calm slate surfaces, one blue for
actions, and strong colour only for risk. Its audience is engineers, DBAs and
security administrators who query production databases, and now the people who
answer for AI agents that do the same.

Three rules decide every colour:

1. **Slate is the ground.** Surfaces, text and lines are one cool grey family.
   Dark is the default theme; light is a full second theme, not a tint.
2. **Blue means "you can act here".** One action blue marks primary buttons,
   the selected item, switches that are on, and the focused control. It never
   marks risk, and nothing else is blue except SQL keywords in the editor.
3. **Strong colour means risk.** Environments and verdicts share one safer →
   riskier ladder (mint, amber, coral). Words and shapes always carry the
   meaning alongside colour. Health is neutral when healthy; Degraded (amber
   square) and Down (coral hollow dot and word) take risk colour because an
   unavailable database is a risk. A cloud label is plain text with no colour.

Implementation: tokens in `web/src/styles/tokens.css`, shared rules in
`web/src/styles/refinement.css`, primitives in `web/src/components/ui/`
(previewed at `/ui?kitchen-sink` in development builds). The source of the look
is the Harbor design canvas; where the canvas and this document differ, this
document describes what is built.

## Tokens and typography

`web/src/styles/tokens.css` is the single foundation source. Existing `--bg`,
`--text`, `--muted`, `--border` and semantic status names are role aliases, not
independent palettes.

| Role              | Token                | Light     | Dark      |
| ----------------- | -------------------- | --------- | --------- |
| Ground            | `--paper`            | `#F4F6F9` | `#0E1217` |
| Surface           | `--surface`          | `#FFFFFF` | `#141920` |
| Subtle fill       | `--subtle`           | `#E9EDF2` | `#1B222B` |
| Hover             | `--hover-fill`       | ink 8%    | `#242D38` |
| Line              | `--rule`             | `#DDE2E9` | `#26303B` |
| Text              | `--ink`              | `#17202B` | `#E4E9EF` |
| Text 2            | `--label-secondary`  | `#4A5665` | `#AAB4C0` |
| Text 3            | `--label-tertiary`   | `#5F6B79` | `#8794A2` |
| Action            | `--action`           | `#3559C7` | `#8FB0FF` |
| Action, hover     | `--action-hover`     | `#2C4BAB` | `#A6C0FF` |
| Action, soft      | `--action-soft`      | `#E8EDFB` | `#1C2740` |
| On action         | `--on-action`        | `#FFFFFF` | `#0E1217` |
| Development       | `--env-dev-text`     | `#17755F` | `#5FD0B3` |
| Development soft  | `--env-dev-soft`     | `#E2F3EE` | `#12302B` |
| Staging           | `--env-staging-text` | `#8A5A0B` | `#EDB95E` |
| Staging soft      | `--env-staging-soft` | `#FBF0D9` | `#33290F` |
| Production        | `--env-prod`         | `#C22F3C` | `#FF9AA0` |
| Production soft   | `--env-prod-soft`    | `#FBE9EB` | `#3A1D22` |
| Production action | `--env-prod-action`  | `#C22F3C` | `#FF8087` |
| On risk           | `--on-risk`          | `#FFFFFF` | `#0E1217` |
| Selection         | `--selection`        | `#D6DEF5` | `#2B3A5C` |
| Syntax keyword    | `--syntax-keyword`   | `#3559C7` | `#8FB0FF` |
| Syntax string     | `--syntax-string`    | `#8C6A2F` | `#E2C08D` |
| Syntax number     | `--syntax-number`    | `#6B4FB0` | `#C7B0F2` |
| Syntax comment    | `--syntax-comment`   | `#5F6B79` | `#8794A2` |

Amber is too light for text on white, so the light theme darkens the staging
and development text while the bands keep the base hues. In the dark theme the
production Run button is coral with dark text; in the light theme it is red
with white text. The four syntax colours are quiet on purpose: the verdict next
to the Run button is the only place that speaks about risk.

### Type

Two faces, both bundled with the console: **Geist** for the interface and
**Geist Mono** for SQL, hosts and identifiers (`@fontsource-variable/geist` and
`@fontsource-variable/geist-mono`, SIL Open Font License 1.1). The console
never asks another server for a font, or for anything else: a security product
must not call out. The stacks are `'Geist Variable', 'Geist', system-ui,
sans-serif` and `'Geist Mono Variable', 'Geist Mono', ui-monospace, Menlo,
monospace`.

Names that people copy and compare (cluster names in tables, schema names,
login names, token hints) use the mono face with the slashed zero, where `0`
and `O`, and `1`, `l` and `I`, are easy to tell apart.

Sizes are 12 (small labels), 13 (data and body), 14 (base), 17 (section
titles), 22 (page titles) and 28 (metrics). Weights are 400 and 600. No italic
face is bundled. Text hierarchy uses three slate tones (text, text 2, text 3),
not opacity.

The theme is set by `web/public/theme.js` before first paint, so the page
never flashes the other theme. It is a file because the server's content
security policy does not allow inline scripts.

### Layout, controls and motion

- **Space over lines.** At most one bordered container per page. The console
  is one surface; schema, editor, results and safety are separated by hairlines.
  Hairlines use the line colour, 0.5px on 2× displays. Tables have no
  vertical rules, an unboxed 12px header and quaternary-fill row hover.
- **Quiet controls.** Buttons are 28 / 32 / 44px (phone primary); one primary
  per view. Icon buttons are borderless with a hover fill and a tooltip.
  `SegmentedControl` (equal segments as wide as the widest label, sliding
  thumb, arrow-key navigation) replaces view/filter tab rows; `Switch` replaces
  checkboxes for settings; checkboxes remain only for row selection. Inputs
  are filled, borderless until hover/focus. Badges are text on a soft fill.
  Lucide icons at 16px, stroke 1.5.
- **Materials.** Sidebar, top bar, menus, popovers, tooltips, toasts and the
  command palette use a translucent material (`saturate(180%) blur(20px)` over
  80% surface) with an opaque fallback for no support and for
  `prefers-reduced-transparency`. Dialogs and sheets are opaque. Only floating
  layers have shadows (0.5px edge + 2/6px + 12/32px soft).
- **Radii are concentric.** Dialog 14, panel 10, control 7; a nested shape uses
  its parent's radius minus the padding between them.
- **Motion.** 120 / 200 / 320ms; sheets ease `cubic-bezier(0.32, 0.72, 0, 1)`,
  popovers `cubic-bezier(0.2, 0, 0, 1)` and grow from their trigger. Dialogs
  fade and scale from 0.98; segmented thumbs slide. Nothing animates on load or
  loops; reduced motion leaves fades only.
- **Focus.** Controls show an outline plus a 3px ring in the action blue; text
  buttons in tables show a 2px action outline. Table rows and scrolling
  regions show a 2px outline in the text colour. All are visible at ≥ 3:1.
  Dialogs focus themselves on open, not their close button, so the close
  tooltip doesn't appear and the first Escape closes the dialog.
- **Preferences apply and persist immediately** in this browser; there is no
  Save step.

## Environment frame

Everything right of the sidebar and below the top bar, on every cluster tab and
the selected-cluster console, carries one band across its top edge:

- Production: an 8px band of static −45° red/soft-red diagonal stripes (6px on
  phones).
- Staging: a 4px solid amber band.
- Development: a 2px muted teal line.

Width and pattern encode risk independently of hue. Nothing animates. Clusters
inventory group headings repeat the treatment as a small swatch. The compact
header has the cluster name, environment word, health/latency, mono host (hidden
on phones; available in Settings and on hover), access and an inline drift link.

Run actions name their target: `Run on production` (production colour), `Run on
staging` (amber family) and `Run` (action blue) in development. Approval-required writes
keep the explicit Request approval action; blocked SQL disables execution. One
Export menu holds CSV/JSON downloads and clipboard formats. Completed results are
their own confirmation (no toast). Phone editors keep at least six visible lines
and the results status line switches to short forms so the first rows stay in
view.

## Pages

- **Overview** opens with a greeting and one line of counts, then _Needs you_:
  approvals waiting for my review, my pending requests and clusters down or
  degraded ("You're all caught up" when empty). Then recent queries
  (Mine/Everyone). The setup checklist is compact, dismissible and hidden once
  complete.
- **Clusters** default to dense rows grouped Production, Staging, Development:
  name/engine monogram, health, cloud and region, truncated host, project,
  your access, last queried. Rows are keyboard navigable. Card view remains
  available.
- **Cluster tabs** (schema, health, access, settings) use grouped-list layouts.
- **Policy** starts with a plain summary ("Reads return at most 1,000 rows.
  Writes are blocked. DDL is blocked."), then grouped rows of label, one-line
  explanation and control with units (seconds in the UI, milliseconds to the
  API). Rows that differ from the environment default show _Customized_ and
  _Reset to default_; a save bar appears only with unsaved changes.
- **Approvals** is a two-pane inbox on desktop with segmented filters and counts;
  phones open the request as a full-screen sheet with sticky actions. Counts
  cover loaded requests, and the page says so. A request an agent asked for
  shows a robot outline instead of initials and says "Asked by agent _name_ for
  _owner_". _What changes_ shows the dry run: the count, how the approval is
  bound in plain words, the notes, and before/after rows (see below). A
  request that ran shows its _Receipt_ (who asked, approved and ran it, rows
  previewed and changed, the binding, the digest with a copy button) with one
  badge for its signature: "Signature valid" (neutral), "Not verified"
  (amber, with a sentence that says to treat it as unproven: a key id proves
  nothing) and "Not valid: this record was changed" (coral). Withdrawn and
  expired requests have neutral badges: they are not a risk, they just will
  not run.
- **History and Audit** group rows under day headings. A History row shows the
  verb, tables and a syntax-tinted SQL preview. An Audit row shows the action
  and one line made from the details the gateway records (a query event says
  that the query was started or refused and that its SQL is in History; it
  holds no SQL). A denied query shows _Blocked_ once. The date-range popover
  offers Today, Last 7 days, Last 30 days and Custom.
- **Audit integrity.** Above the filters, one quiet line states the hash
  chain: "Chain intact up to _time_ · _N_ rows sealed · _M_ waiting". It is
  read again every fifteen seconds and never from a cache. Rows that another
  master key sealed get an amber _Partly verified_ badge and a sentence; the
  line then never says "intact". A break is the only risk state: one alert
  with a coral _Chain broken_ badge, what happened, what it means, the
  position and the event, and what to do. A long wait for sealing is a
  sentence, not an alert. Each row has a _Sealed_ column with a word and a
  shape (lock: Sealed; clock: Waiting). _Verify now_ shows its answer next to
  the button and keeps it there; a refusal for too many checks says how long
  to wait.
- **Users and Access** use list rows with quiet badges; destructive actions live
  in a row menu with confirmation; _Added by_ shows a person or "—".
- **Settings, Preferences, Login, command palette, dialogs, toasts, empty states,
  skeletons and errors** all use the shared primitives.

## Contrast measurements

Computed from the token values with the WCAG 2 formula (lowest first per
theme). Every pair meets AA for normal text (4.5:1). The browser tests also
scan the rendered screens with axe in both themes.

| Theme | Pair                      | Text      | Background | Ratio   | AA   |
| ----- | ------------------------- | --------- | ---------- | ------- | ---- |
| Dark  | tertiary on surface       | `#8794A2` | `#141920`  | 5.71:1  | Pass |
| Dark  | syntax comment            | `#8794A2` | `#141920`  | 5.71:1  | Pass |
| Dark  | development on its soft   | `#5FD0B3` | `#12302B`  | 7.52:1  | Pass |
| Dark  | production on its soft    | `#FF9AA0` | `#3A1D22`  | 7.53:1  | Pass |
| Dark  | secondary on raised       | `#AAB4C0` | `#1B222B`  | 7.63:1  | Pass |
| Dark  | text on production button | `#0E1217` | `#FF8087`  | 7.78:1  | Pass |
| Dark  | staging on its soft       | `#EDB95E` | `#33290F`  | 7.99:1  | Pass |
| Dark  | action on surface         | `#8FB0FF` | `#141920`  | 8.26:1  | Pass |
| Dark  | syntax keyword            | `#8FB0FF` | `#141920`  | 8.26:1  | Pass |
| Dark  | secondary on surface      | `#AAB4C0` | `#141920`  | 8.40:1  | Pass |
| Dark  | production on surface     | `#FF9AA0` | `#141920`  | 8.73:1  | Pass |
| Dark  | action on ground          | `#8FB0FF` | `#0E1217`  | 8.79:1  | Pass |
| Dark  | text on action button     | `#0E1217` | `#8FB0FF`  | 8.79:1  | Pass |
| Dark  | secondary on ground       | `#AAB4C0` | `#0E1217`  | 8.95:1  | Pass |
| Dark  | syntax number             | `#C7B0F2` | `#141920`  | 9.18:1  | Pass |
| Dark  | syntax string             | `#E2C08D` | `#141920`  | 10.22:1 | Pass |
| Dark  | text on selected row      | `#E4E9EF` | `#1C2740`  | 12.17:1 | Pass |
| Dark  | text on raised            | `#E4E9EF` | `#1B222B`  | 13.13:1 | Pass |
| Dark  | text on surface           | `#E4E9EF` | `#141920`  | 14.46:1 | Pass |
| Dark  | text on ground            | `#E4E9EF` | `#0E1217`  | 15.39:1 | Pass |
| Light | production on its soft    | `#C22F3C` | `#FBE9EB`  | 4.77:1  | Pass |
| Light | development on its soft   | `#17755F` | `#E2F3EE`  | 4.88:1  | Pass |
| Light | syntax string             | `#8C6A2F` | `#FFFFFF`  | 4.98:1  | Pass |
| Light | staging on its soft       | `#8A5A0B` | `#FBF0D9`  | 5.23:1  | Pass |
| Light | tertiary on surface       | `#5F6B79` | `#FFFFFF`  | 5.43:1  | Pass |
| Light | syntax comment            | `#5F6B79` | `#FFFFFF`  | 5.43:1  | Pass |
| Light | production on surface     | `#C22F3C` | `#FFFFFF`  | 5.58:1  | Pass |
| Light | text on production button | `#FFFFFF` | `#C22F3C`  | 5.58:1  | Pass |
| Light | action on ground          | `#3559C7` | `#F4F6F9`  | 5.70:1  | Pass |
| Light | action on surface         | `#3559C7` | `#FFFFFF`  | 6.17:1  | Pass |
| Light | text on action button     | `#FFFFFF` | `#3559C7`  | 6.17:1  | Pass |
| Light | syntax keyword            | `#3559C7` | `#FFFFFF`  | 6.17:1  | Pass |
| Light | syntax number             | `#6B4FB0` | `#FFFFFF`  | 6.23:1  | Pass |
| Light | secondary on ground       | `#4A5665` | `#F4F6F9`  | 6.90:1  | Pass |
| Light | secondary on surface      | `#4A5665` | `#FFFFFF`  | 7.47:1  | Pass |
| Light | text on selected row      | `#17202B` | `#E8EDFB`  | 14.04:1 | Pass |
| Light | text on ground            | `#17202B` | `#F4F6F9`  | 15.18:1 | Pass |
| Light | text on surface           | `#17202B` | `#FFFFFF`  | 16.43:1 | Pass |

## Agents and the database setup check

Two screens belong to the agent gate.

**Agents** (`/agents`) lists the programs that query for a person. Each row
has the agent, its one owner, what it can reach, its level and its state. The
detail has what it can reach (each database with its environment word and
cloud label), the guardrails, its tokens and the tools it gets.

The guardrail texts say only what is true for every database. They do not
claim that protected values never leave the gateway, or that other tables are
hidden from the agent: on a database without an agent login the gateway's own
checks are the only protection, and the texts say which layer does what. A
token is shown one time, in the dialog that creates it, and afterwards only as
`vda_agent_••••` with its last four characters.

**Agent login** (a tab on a PostgreSQL cluster, for its administrators) is the
database setup check. One badge states the result in the words of the person
who must act: In sync (mint), Check needed (amber), Too open, Could not check
and Password needed (coral), Not checked (neutral). A result from before a
policy or cluster change is never shown as the present state: the badge says
Check needed until a new check has run. Findings are grouped as "Must be repaired" and "Worth a look", each
with the object and one sentence. The setup script is shown as text to copy or
download; the console never runs it.

Neither screen uses risk colour for anything but a real risk state (Too open,
Could not check, Password needed, a paused agent).

## Changed values

Preview tables (before and after a write) follow the result tables: no
vertical rules, and a column says in its header what is special about it:
`· written` when the statement writes it, `· masked` when it is protected,
`· hidden` for a new value that may not be shown for another reason (computed
from something protected, or an `INSERT` without a column list). A written
column is marked even when its values are hidden, so two tables that look the
same still say what changes.

A changed value in the after table is **bold and underlined** on a subtle
fill, and screen readers hear "Changed:" before it, so the change never
depends on colour. Cells are marked only when the rows can be paired for
certain: by a column in both samples that is shown, not written, and unique,
with no row cut from either sample. Otherwise no cell is marked and one line
says "Rows cannot be matched one to one here; written columns are marked." A
guessed mark would be worse than none.

The key column and the written columns come first, so a phone shows the change
without scrolling; long values are cut in the middle on a phone
(`0000…00002041`) and stay whole on hover and for screen readers. "showing 20
of 47" says when the server cut the sample. The binding sentence follows the
request: "It will run only on these exact rows" while it can run, "It was
bound to these exact rows" after.

Dialogs give focus back to the control that opened them. When the action
removed or disabled that control, focus goes to a stable place in the same
area (`data-focus-return` on the area, `data-focus-target` with
`tabIndex={-1}` on the element), never to the page itself.

## The pre-flight bar

The console's verdict lives in one bar under the SQL editor, next to the
button it explains. It is always on screen, also when the safety panel is
closed and on a phone.

- **Three states**, in words and with a mark, never by colour alone: _Safe to
  run_, _Needs approval_, _Blocked_. The colour of the mark and of the bar's
  left edge only repeats the state.
- **One sentence of why**, and when the guard changes the SQL, exactly what
  it adds (`LIMIT 1001`), marked as code.
- **One next step.** Run; open the approval request; apply the guard's fix;
  or, when only an administrator can help, no button and a sentence that says
  who. The server decides the state and the step (`preflight` in the analyze
  answer); the console never works it out from the verdict when the server
  sent one.
- **While the check runs** the last answer stays, dimmed, with "Updating…",
  and the button waits. When the check fails the bar says so and its one
  action is "Check again". Nothing runs on a stale or failed check.
- **For assistive technology** the bar is a group with one polite status
  line. The line is set 700 ms after an answer has settled and only when its
  text differs from what was said last, so typing does not make it speak.
  The line names the state in other words ("Check passed.", "Approval
  needed.", "Not allowed.") so that the label on screen stays the one element
  with its text.
- **On a phone** the sentence goes under the state and the button. With a
  safe statement that the guard changes, the line shows what the guard adds;
  the general sentence and the reason stay for the status line.

The safety panel holds the details (risk, issues, suggestions, the SQL that
runs) and no longer repeats the verdict in the console. On the approval
screen, which has no bar, it still shows it.

The agent session view follows the same rule for its marks: _Done_, _Needs a
person_, _Refused_ and _Failed_ are words with an icon; the coloured edge of
a step repeats them.

## Known gaps

These need API support before the console can show them exactly:

1. Access shows "—" for _Added by_: `Grant.created_by` is only a UUID. A
   nullable grantor object `{id, name, email}` would let it show a person.
2. _Last queried_ on the clusters list is derived from the caller's 200 most
   recent history records; "—" means "not in that window". A per-cluster
   last-query timestamp would make it exact.
3. Connected clusters report `postgres` or `mysql` only, so MariaDB clusters
   can't show their own engine marker once imported.
4. Approval counts and the History/Audit date range cover loaded records only
   (the UI says so). Server-side counts and `from`/`to` filters would fix that.

Discovery and inventory tables scroll horizontally on phones to keep their
columns rather than collapsing into cards.

## Verification

`npm run test:e2e` scans every route, including Agents and the Agent login tab,
with axe at 1440 × 900 and 390 × 844 in both themes, and checks that the console loads its fonts from its own bundle and
calls no other host. Recompute the contrast table when a token changes, and keep
both clean when changing tokens or primitives.
