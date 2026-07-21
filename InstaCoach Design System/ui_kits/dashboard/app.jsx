/* InstaCoach kit — app shell + routing. Loaded last. */
const AppIcon = window.Icon;

const NAV = [
  { id: "today", label: "Today", icon: "home" },
  { id: "plan", label: "Plan", icon: "target" },
  { id: "journal", label: "Journal", icon: "journal" },
  { id: "coach", label: "Coach", icon: "message" },
  { id: "progress", label: "Progress", icon: "chart" },
];

const TITLES = {
  today: { h: "Good morning, Maya", d: "Wednesday, June 6 · Week 3 of your plan" },
  plan: { h: "Your 4-week plan", d: "Grow into the director conversation" },
  coach: { h: "Coach Wren", d: "Usually replies in a moment" },
  journal: { h: "Journal", d: "Your reflections, in one calm place" },
  progress: { h: "Progress", d: "How your momentum is trending" },
};

function Sidebar({ screen, go }) {
  const { Logo } = window;
  return (
    <aside className="sidebar">
      <Logo />
      <div className="sidebar__section">Coaching</div>
      {NAV.map((n) => (
        <button key={n.id} className={`navitem${screen === n.id ? " navitem--active" : ""}`} onClick={() => go(n.id)}>
          <AppIcon name={n.icon} />
          {n.label}
          {screen === n.id ? <span className="navdot" /> : null}
        </button>
      ))}
      <div className="sidebar__spacer" />
      <button className="navitem" onClick={() => go("settings")}>
        <AppIcon name="settings" /> Settings
      </button>
      <div className="sidebar__user">
        <span className="avatar">MO</span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div className="name">Maya Okafor</div>
          <div className="sub">Product Lead</div>
        </div>
        <AppIcon name="chevron-right" size={16} style={{ color: "var(--text-subtle)" }} />
      </div>
    </aside>
  );
}

function Placeholder({ title }) {
  return (
    <div className="card" style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 12, padding: 56, textAlign: "center" }}>
      <div className="lrow__icon" style={{ width: 52, height: 52 }}><AppIcon name="bookmark" size={24} /></div>
      <div className="serif" style={{ fontSize: 22 }}>{title} is sketched in</div>
      <p className="muted" style={{ margin: 0, maxWidth: 380, lineHeight: 1.55 }}>
        This surface isn't part of the recreation yet. The shell, Today, Plan, and Coach screens show the full system in use.
      </p>
    </div>
  );
}

function App() {
  const [authed, setAuthed] = React.useState(false);
  const [screen, setScreen] = React.useState("today");
  const { SignIn, Today, Plan, Coach } = window;

  if (!authed) return <SignIn onSignIn={() => setAuthed(true)} />;

  const t = TITLES[screen] || { h: screen, d: "" };
  const isChat = screen === "coach";

  return (
    <div className="app">
      <Sidebar screen={screen} go={setScreen} />
      <main className="main" style={isChat ? { display: "flex", flexDirection: "column", overflow: "hidden" } : null}>
        <div className="topbar">
          <div className="topbar__title">
            <span className="h">{t.h}</span>
            <span className="d">{t.d}</span>
          </div>
          <div className="topbar__actions">
            <button className="iconbtn" aria-label="Search"><AppIcon name="search" /></button>
            <button className="iconbtn" aria-label="Notifications"><AppIcon name="bell" /></button>
            <button className="btn btn--primary btn--sm" onClick={() => setScreen("coach")}>
              <AppIcon name="sparkles" size={16} /> New session
            </button>
          </div>
        </div>
        {isChat ? (
          <Coach />
        ) : (
          <div className="content">
            {screen === "today" && <Today go={setScreen} />}
            {screen === "plan" && <Plan />}
            {["journal", "progress", "settings"].includes(screen) && <Placeholder title={TITLES[screen] ? TITLES[screen].h : "This"} />}
          </div>
        )}
      </main>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
