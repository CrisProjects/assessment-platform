# InstaCoach · Dashboard UI kit

A high-fidelity, clickable recreation of the InstaCoach coaching web app. Open
`index.html`.

## Flow
1. **Sign in** — split brand panel (forest) + form. Any submit (or "Continue with
   SSO" / "Start your first session") enters the app.
2. **Today** — the home surface: today's focus card, 4-week plan ring, stat cards
   (next check-in, streak, momentum), a "from your coach" nudge, and recent
   reflections.
3. **Plan** — the 4-week plan overview, week tabs, goal cards with progress, and
   this week's sessions.
4. **Coach** — a live chat with Coach Wren. Type and press Enter (or the send
   button); the coach replies with a short scripted message and a typing indicator.

Journal / Progress / Settings are intentionally stubbed with a disclaimer — they
aren't part of this recreation.

## Files
- `index.html` — shell; loads React + Babel, `../../styles.css`, `kit.css`, then the
  JSX files in order.
- `kit.css` — layout + component styles, all built on the design tokens.
- `icons.jsx` — inline Lucide-geometry icon set (`window.Icon`).
- `screens.jsx` — `SignIn`, `Today`, `Plan`, shared `Logo` / `Ring`.
- `coach.jsx` — the `Coach` chat screen.
- `app.jsx` — sidebar, routing, topbar; mounts `<App>`.

## Notes
- This kit is self-contained (it does not load `_ds_bundle.js`) so it renders
  identically online and offline. It mirrors the published primitives 1:1 visually
  via shared tokens; for production, prefer the real components in `components/`.
- Fake data lives at the top of `screens.jsx` (`DATA`).
