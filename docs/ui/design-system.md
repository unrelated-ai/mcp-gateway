# UI Design System

The Web UI is a dark "instrument panel" for the gateway control plane. One vocabulary of
tokens and components covers the whole app; pages never hand-roll their own buttons,
badges, tabs, tables, or colors.

## Tokens (defined in `ui/app/globals.css` `@theme`)

Use semantic tokens only. Raw Tailwind palette colors (`zinc-*`, `violet-*`, `red-*`,
`emerald-*`, `sky-*`, `blue-*`, …) are not allowed in pages or components.

| Token | Utility examples | Use for |
| --- | --- | --- |
| `bg` | `bg-bg` | App background |
| `surface` | `bg-surface` | Cards, panels, sidebar |
| `raised` | `bg-raised` | Hover fills, nested chips, skeletons |
| `overlay` | `bg-overlay` | Toasts, floating panels |
| `well` | `bg-well` | Inset code/endpoint wells, form controls |
| `edge` / `edge-strong` | `border-edge`, `border-edge-strong` | Hairlines / control borders |
| `fg` / `muted` / `faint` | `text-fg`, `text-muted`, `text-faint` | Text hierarchy (primary / secondary / hints) |
| `accent`, `accent-strong`, `accent-hover` | `text-accent`, `bg-accent-strong` | Brand iris. Active nav, primary buttons, focus rings |
| `ok`, `warn`, `danger`, `info` | `text-ok`, `bg-danger/10`, … | Functional state only — never decoration |

Soft fills use opacity modifiers (`bg-ok/10`, `border-danger/25`), not separate tokens.

Fonts: `font-sans` = IBM Plex Sans (UI text), `font-mono` = IBM Plex Mono (endpoints, IDs,
keys, JSON, metrics, eyebrow labels). Anything machine-readable renders in mono.

## Principles

- **Flat and precise.** No gradients, no glow/colored shadows, no backdrop-blur on cards,
  no `animate-pulse` status dots. Shadows only on true overlays (modal, drawer, toast).
- **Radius scale:** controls `rounded-md`, cards/wells `rounded-lg`, overlays `rounded-xl`.
  Pills exist only inside `Badge`/`Toggle`.
- **Silkscreen eyebrows.** Section labels, stat labels, and table headers use the `eyebrow`
  utility class (mono, 11px, uppercase, tracked). This is the app's structural signature.
- **Status LEDs.** Live/enabled state is a small square dot (`size-1.5 rounded-[1px]`),
  steady, `bg-ok` when live, `bg-faint/60` when off. Built into `Badge dot` and
  `EndpointWell`.
- **Endpoints are the hero artifact.** Every MCP URL renders through `EndpointWell`.
- **Motion:** `animate-rise` / `animate-fade` for overlays only; everything else uses
  150ms color transitions. `prefers-reduced-motion` is respected globally.
- **One color-semantics prop:** `tone` = `neutral | accent | ok | warn | danger | info`
  (type `Tone` from `@/components/ui`). "danger" is the only word for red; "ok" for green.
- **Sizes:** `sm | md | lg`. **Copy props:** always `value`.
- No nested interactive elements. Clickable cards use the stretched-link pattern
  (see `app/profiles/page.tsx` `ProfileCard`): the title `Link` gets
  `after:absolute after:inset-0`, sibling controls get `relative z-10`.

## Components (`ui/components/ui`)

| Component | API essentials |
| --- | --- |
| `Button` | `variant: primary\|secondary\|ghost\|danger`, `size: sm\|md\|lg`, `loading` |
| `IconButton` | `label` (required, becomes aria-label), `size: sm\|md` |
| `Input`, `Textarea`, `Select` | `label`, `hint`, `error` + native props; auto `id`/aria wiring |
| `Checkbox`, `Toggle` | `checked`, `onChange(bool)`, `label`, `description` |
| `Badge` | `tone`, `dot`; `StatusBadge enabled`; `AuthModeBadge mode` |
| `Callout` | `tone`, `size`, `title` |
| `Card` (+ `CardHeader/Content/Title/Description`) | plain container; `hover` for link cards |
| `SectionCard` | `title` (renders as eyebrow), `subtitle`, `right` — labeled panels on detail pages |
| `Tabs` | `items: {value,label,count?,disabled?}[]`, `value`, `onChange` — proper tablist a11y |
| `Table`, `THead`, `TBody`, `TR`, `TH`, `TD` | data tables; TH renders as eyebrow |
| `Modal`, `ModalActions`, `ConfirmModal` | focus-trapped, `role=dialog`; `ConfirmModal danger/requireText` |
| `Drawer` | right-side inspector panel (audit details, etc.) |
| `Stat` | `label` (eyebrow), `value` (mono), `tone`, `hint` |
| `EndpointWell` | `url`, `live` — the signature endpoint treatment with LED + copy |
| `CopyButton` | `value`, `variant: button\|icon` |
| `CopyBlock` | `value`, `label`, `language`, `compact` — highlighting is React nodes, never innerHTML |
| `EmptyState` | `icon`, `title`, `description`, `action` |
| `Spinner`, `Skeleton`, `SkeletonRows` | loading states; never hand-roll spinners |
| `ToastViewport` | reads `useToastStore`; store variants stay `success\|error\|info` |

Layout (`ui/components/layout`): `AppShell` (sidebar + tenant indicator + lock),
`PageHeader` (`title`, `description`, `actions`, `breadcrumb`), `PageContent` (`width`).

## Writing rules

Sentence case everywhere ("Create profile", not "Create Profile"). Buttons name the exact
action; the same verb persists through the flow (button "Create profile" → toast
"Profile created"). Errors say what went wrong and what to do next, without apologizing.
Empty states invite the first action.

## Server routes

All `app/api/tenant/**` handlers go through `proxyTenantRequest` from
`ui/src/lib/server/gateway-proxy.ts` (single auth path, timeout, cross-site check,
uniform error mapping). Never re-hardcode the cookie name or the fetch boilerplate.
