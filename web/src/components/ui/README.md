# Visp design system

Use `index.tsx` primitives for actions, fields, selects, tabs, dialogs,
confirmations, badges, tooltips and list feedback. Radix handles focus containment
and keyboard behavior. `toast.tsx` supplies error and background-action feedback;
`brand.tsx` owns the gateway mark. Preview at `/ui?kitchen-sink` as an admin in
development; the production route is unavailable.

`styles/tokens.css` owns all shared tokens. Atkinson Hyperlegible Next is the UI
font; Atkinson Hyperlegible Mono is reserved for SQL, hosts, IDs and numeric table
cells. The scale is 12 / 13 / 14 / 16 / 20 / 26px. Controls use 6px radii, panels
8px and dialogs 12px. Only floating layers have shadows. Focus uses a 2px ink
outline with a 2px offset. Selection is neutral gray.

Primary actions are ink. Color denotes environments and SQL guard verdicts.
`Badge` exposes neutral / verdict / status variants; status text is
capitalized and neutral, with explicit words.
See `docs/DESIGN.md` for color pairs, contrast measurements and the environment
frame. Production has a striped 6px rail, staging a solid 4px rail and development
a muted teal 2px rail. On phones the rail becomes a top band.

The app occupies the viewport; main content scrolls independently. Console routes
use a bounded editor/results split and collapsible schema/safety columns. Standard
buttons are 36px tall; mobile approval actions are 40px. Use sentence case and
explicit action names, preserve API error messages and offer retries for failed
reads. Destructive confirmations state their scope.

## Verdicts and actors

The gate has one vocabulary, used on every screen: `VerdictChip` from
`verdict.tsx`, with the value mapped from the API by `lib/verdict.ts`
(`verdictOfAnalysis`, `verdictOfStep`, `verdictOfHistory` and the rest; never
map a raw status by hand).

- **Allowed**: the gate let the statement or call through as written.
- **Masked**: it ran, and the policy hid one or more columns of the rows.
- **Held**: a write waits for a person to approve it (dashed edge: not final).
- **Blocked**: the gate refused it, or a reviewer rejected the request.

A failure that is not a gate decision (a timeout, an expired request) has no
verdict: the mapper returns `undefined`; show the run status instead.

Rule: the status of a guard decision is a `VerdictChip`; who did it is an
`ActorBadge` (`kind="agent"` shows an inverted "Agent" tab, then name and
client; `kind="human"` an outline person and a name). Do not use `Badge`
tones or colour alone for either. Colours are the `--verdict-*-fg/-bg/-line`
tokens in `styles/tokens.css`; text on its ground is AA in both themes.
Screen styles go in `styles/redesign-<screen>.css`, shared ones in
`styles/redesign.css`.

## Risk, environment, SQL and time

One look each, on every screen (shown on `/ui`):

- `EnvBadge` (`index.tsx`): where something runs. A small tinted mark;
  production is filled and striped, so it is never missed. Never write the
  environment as a coloured word by hand.
- `RiskMeter` (`risk.tsx`): the guard's risk as four steps and the word
  ("High risk"). `compact` drops the visible "risk" in dense rows; a screen
  reader still hears it. Not the console's safety panel, which keeps its
  full-width scale with every level named.
- `SqlText` (`sql-preview.tsx`): SQL with keywords and strings marked, for
  inside a `pre` or `code`; `SqlPreview` wraps it in `code`.
- Times (`time.tsx`): `RelativeTime` in lists, `ExpiryTime` for deadlines,
  `formatTime` (date, time and zone) where one moment is the subject, and
  `ClockTime` for a run of events under a heading that already gives the day
  and the zone, such as a session's steps. All honour the UTC preference.
