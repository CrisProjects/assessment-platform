# InstaCoach Design System

> Calm, supportive coaching for your career and life. *"Here's your next move."*

InstaCoach is an executive- and life-coaching platform for professionals — and
anyone trying to make their career or life a little better. The product pairs an
AI coach with structured plans, reflections, and check-ins. The brand's job is to
feel **calm, grounded, and quietly premium**: a steady presence that gives you
the next small, clear step without hype or pressure.

This repository is the **single source of truth** for that brand — design tokens,
foundation specimens, reusable React components, and full-screen UI kits. A
compiler indexes it automatically; consuming projects link one file (`styles.css`)
and pull components from the generated runtime bundle.

**Primary surface:** web app / dashboard (responsive).
**Personality:** calm & supportive · smart & concise.
**Direction:** "Tide" — serene ocean blue + warm gold on a cool off-white; editorial serif headlines.

---

## Sources

This system was designed **from scratch** — there was no prior codebase, Figma file,
or brand kit. If/when those exist, record them here so future contributors can trace
decisions back to source:

- Codebase: _none provided_
- Figma: _none provided_
- Brand guidelines: _none provided_

Fonts are loaded from the **Google Fonts CDN** (Newsreader + Hanken Grotesk), not
self-hosted binaries — see Caveats at the bottom.

---

## Content fundamentals

How InstaCoach writes. The voice is a great coach: **smart, concise, and warm
without being soft.** It respects the user's time and intelligence.

**Voice principles**
- **Direct, not bossy.** State the next move plainly. "Reframe one hard
  conversation." not "You might want to consider possibly reframing…".
- **Concise.** Short sentences. One idea per line. Cut throat-clearing.
- **Second person, present tense.** Talk *to* the user ("you"), as a coach would.
  The product refers to itself sparingly and never as "we the company."
- **Encouraging, never gushing.** Acknowledge effort quietly ("On track."),
  don't cheerlead ("Amazing job!!! 🎉").
- **Calm under pressure.** Even errors and overdue items stay composed —
  "Let's pick this back up." not "You missed it!"

**Tone by surface**
- *Headlines (serif):* reflective, human, a touch literary — "Begin where you are."
- *UI labels & buttons:* plain verbs — "Start session", "Save reflection", "Later".
- *Coach messages:* conversational, specific, one actionable step at a time.
- *System / empty states:* gentle and orienting — "Nothing due today. A good time
  to reflect."

**Casing & mechanics**
- **Sentence case everywhere** — headings, buttons, labels, menu items. No Title Case.
- Eyebrows / overlines may be ALL-CAPS with wide tracking (the only uppercase use).
- One space after periods. Oxford comma. Numerals for data ("3 sets", "12 min").
- Avoid jargon and corporate-speak ("synergy", "leverage", "circle back").

**Emoji:** **not used** in product UI or brand copy. The system communicates warmth
through type, color, and pacing — not emoji. (A user's own journal entries are their
business; the *product* voice stays emoji-free.)

**Sample copy**
- Hero: *"Coaching that meets you mid-week."* / "Your next move, every day — built
  around your goals, your calendar, and your pace."
- CTA: "Start your first session" · "Set this week's focus"
- Coach nudge: "You named avoiding the 1:1 as a pattern. Want to plan how you'll
  open it?"
- Empty: "No reflections yet. The first one is the hardest — start with a sentence."

---

## Visual foundations

The look is **editorial and unhurried**. Generous whitespace, a cool off-white canvas,
deep ocean blues for substance, and a single gold accent used like a highlighter
— sparingly, for moments that matter.

**Color**
- **Ocean blue** is the brand (`--primary` #2C5AA8, ink #14233F). It carries
  buttons, brand fills, headings on light grounds, and the dark "inverse" surfaces.
- **Warm gold** (`--accent` #C49A52) is a *sparing* sunrise accent — a streak under a word,
  a small marker, an active dot. Never large fills; never two golds on one screen.
- **Cool off-white** (`--surface-page` #F1F4F9) is the default canvas; cards are **white**.
  This card-on-tinted-canvas contrast is core to the calm feel — avoid flat pure-white pages.
- **Neutrals are cool** (mist scale), slightly blue-tinted, never warm gray.
- **Status hues are low-chroma and calm**: muted green (success), soft amber
  (warning), terracotta-clay (danger — never a fire-engine red), dusty teal (info).
- Vibe of imagery: **cool, serene natural light, soft focus** — water, sky, calm
  workspaces, daylight interiors. No harsh studio shots, no neon.

**Typography**
- **Newsreader** (serif) for display & headings — literary, optically-sized, a human
  warmth. Used at medium weight with tight tracking (`--tracking-display`).
- **Hanken Grotesk** (sans) for everything functional — body, labels, data, buttons.
  Humanist, friendly, highly legible.
- Reserve the serif for *expressive* moments (page titles, pull-quotes, the focus of
  a card). Don't set forms or dense data in serif.
- Italic serif is used for short reflective asides / the tagline.

**Spacing & layout**
- 4px base grid. Layouts **breathe** — prefer the larger spacing steps for section
  rhythm (`--space-12`/`--space-16`), smaller for component internals.
- Max content widths are modest (`--container-md` 860px for reading) — calm, not
  sprawling. Left sidebar nav at `--sidebar-w` 260px; topbar at 64px.

**Shape & elevation**
- **Rounded, soft corners**: `--radius-lg` (14px) for cards, `--radius-md` (10px)
  for buttons/inputs, `--radius-pill` for chips/tags.
- **Shadows are gentle, diffuse, and ocean-navy-tinted** (not black) — they whisper.
  Cards typically use `--shadow-sm`; raised/floating layers `--shadow-md`/`lg`.
  No hard drop shadows, no neumorphism.
- **Borders are hairline and warm** (`--border-subtle`/`-default`, sand-tinted).
  Cards combine a soft shadow with a 1px subtle border on the cool canvas.
- No left-accent-border cards, no heavy outlines, no glassmorphism by default.
  (One exception: dark navy surfaces may use a subtle inner highlight.)

**Motion**
- **Short, soft ease-outs.** `--dur-base` 200ms with `--ease-out`. The brand never
  bounces or springs — that reads as hype. Transitions fade and gently slide
  (≤8px). Respect `prefers-reduced-motion`.
- **Hover:** surfaces lift slightly (shadow `sm`→`md`) and/or wash to
  `--surface-hover` (a pale sky tint). Primary buttons darken to `--primary-hover`.
- **Press:** a brief darken to `--primary-active` plus a ~1px nudge down / 0.99
  scale — a settle, not a pop. No color *lightening* on press.
- **Focus:** a soft 3px blue ring (`--ring`), never a default browser outline.

**Backgrounds**
- Mostly the flat cool canvas. Occasional **full-bleed serene photography** (water,
  sky) for hero/marketing moments, always with a navy protection gradient for legible text.
- No busy patterns, no mesh gradients, no purple AI-style gradients. A very subtle
  grain is acceptable on large dark navy panels.

---

## Iconography

InstaCoach uses **[Lucide](https://lucide.dev)** — open-source, MIT-licensed,
**stroke-based** icons (2px round caps/joins). Their light, even, rounded line
matches the calm/editorial tone far better than filled or sharp icon sets.

- **Style:** outline only, 2px stroke, `currentColor` so icons inherit text color.
- **Sizes:** 16px (inline / dense), 20px (default UI), 24px (nav / headers).
- **Don't** mix in filled icon sets, emoji-as-icons, or multicolor glyphs.
- **Active/selected** nav items may pair a blue icon with a gold active dot.

**How it's loaded:** via CDN (no build step). In HTML, include
`<script src="https://unpkg.com/lucide@latest/dist/umd/lucide.js"></script>` then
`lucide.createIcons()`, and place icons as `<i data-lucide="compass"></i>`.
Common glyphs in this product: `compass`, `target`, `calendar-check`,
`message-circle`, `sparkles`, `clock`, `check`, `arrow-right`, `chevron-right`,
`bookmark`, `flame`, `notebook-pen`, `settings`, `bell`, `user`.

> **Substitution note:** the original brand had no icon set, so Lucide is a
> deliberate, documented choice — not a stand-in for something proprietary.
> Swap it only with the user's sign-off.

A few small **unicode marks** appear as lightweight accents in specimens
(◷ for "focus/time", • for active dots) but the product proper uses Lucide.

---

## Index — what's in this system

**Foundations (root)**
- `styles.css` — global entry point (link this). `@import`s everything below.
- `tokens/fonts.css` — Newsreader + Hanken Grotesk (Google Fonts CDN).
- `tokens/colors.css` — primitives (ocean / gold / mist / status) + semantic aliases.
- `tokens/typography.css` — families, weights, type scale, tracking.
- `tokens/spacing.css` — 4px spacing scale, radii, layout, motion.
- `tokens/elevation.css` — soft ocean-tinted shadow scale + focus ring.

**Specimen cards** (`guidelines/` — render in the Design System tab)
- Colors: ocean, gold, mist, status, semantic roles.
- Type: display (Newsreader), body/UI (Hanken Grotesk), type scale.
- Spacing: spacing scale, radii, elevation, motion.
- Brand: logo, logo on navy, voice & tone, iconography.

**Assets** (`assets/`)
- `logo/instacoach-mark.svg` — circular app mark (ocean blue, font-independent geometry).
- `logo/instacoach-wordmark.svg` — full lockup (ocean on light).
- `logo/instacoach-wordmark-cream.svg` — full lockup (cool white on dark navy).
- Iconography via **Lucide** (CDN, no binaries stored).

**Components** (`components/` — reusable React primitives)
Mounted via the generated bundle as `window.<Namespace>.<Component>` — run
`check_design_system` for the exact namespace. Each directory has a `.d.ts`,
`.prompt.md`, and a `@dsCard` HTML demo.
- `forms/` — **Button**, **IconButton**, **Input**, **Textarea**, **Select**,
  **Checkbox**, **Switch**.
- `data-display/` — **Card**, **Badge**, **Tag**, **Avatar**, **Progress** (bar + ring).
- `navigation/` — **Tabs** (underline + pill).
- `feedback/` — **Toast**, **Dialog**.
- Starting points: **Button** (Forms), **Card** (Layout), and the dashboard screen.

**UI kits** (`ui_kits/`)
- `dashboard/` — the InstaCoach coaching web app. Interactive: sign-in → Today
  (focus, plan ring, coach nudge, reflections) → Plan (weekly goals + sessions) →
  Coach (live chat with canned replies). Built from `icons.jsx`, `screens.jsx`,
  `coach.jsx`, `app.jsx` + `kit.css`, all styled with the design tokens.

**Other**
- `SKILL.md` — lets this whole system run as a downloadable Claude Skill.
- `readme.md` — this file.

---

## Caveats
- **Fonts** are loaded from Google Fonts CDN, not self-hosted `.woff2` binaries, so
  the compiler reports 0 declared `@font-face` fonts. Rendering is correct; for fully
  offline use, self-host the two families and replace the `@import` in
  `tokens/fonts.css` with `@font-face` rules.
- **Icons** use Lucide (a documented substitution, since no icon set existed).
