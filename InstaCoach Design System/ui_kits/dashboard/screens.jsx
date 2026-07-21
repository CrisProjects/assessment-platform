/* InstaCoach kit — screens. Loaded after icons.jsx. */
const Icon = window.Icon;

const DATA = {
  user: { name: "Maya Okafor", role: "Product Lead · Northwind" },
  coach: { name: "Coach Wren", role: "Your coach" },
  focus: "Reframe one hard conversation.",
  planPct: 68,
  goals: [
    { title: "Lead with clarity under pressure", tag: "Communication", pct: 72 },
    { title: "Set boundaries without guilt", tag: "Wellbeing", pct: 55 },
    { title: "Grow into the director conversation", tag: "Career", pct: 40 },
  ],
  sessions: [
    { icon: "calendar-check", title: "Career growth check-in", when: "Today · 4:00 PM", tone: "brand" },
    { icon: "clock", title: "Weekly reflection", when: "Thu · 8:30 AM", tone: "neutral" },
    { icon: "target", title: "Boundaries practice", when: "Fri · 12:00 PM", tone: "neutral" },
  ],
  reflections: [
    { title: "The 1:1 went better than I feared", date: "Yesterday", tag: "Confidence" },
    { title: "Noticed I avoid conflict when tired", date: "Mon", tag: "Patterns" },
    { title: "Said no to the extra project", date: "Last week", tag: "Boundaries" },
  ],
};

function Logo() {
  return (
    <div className="sidebar__logo">
      <img src="../../assets/logo/instacoach-mark.svg" alt="" />
      <span>InstaCoach</span>
    </div>
  );
}

/* ------------------------------------------------------------------ Sign in */
function SignIn({ onSignIn }) {
  return (
    <div className="signin">
      <div className="signin__brand">
        <div className="lock">
          <img src="../../assets/logo/instacoach-wordmark-cream.svg" alt="InstaCoach" style={{ height: 40, width: "auto" }} />
        </div>
        <div className="signin__pitch">
          <h1>Coaching that meets you mid&#8209;week.</h1>
          <p>Your next move, every day — built around your goals, your calendar, and your pace.</p>
        </div>
        <div className="signin__foot">Trusted by 40,000+ professionals growing on their own terms.</div>
      </div>
      <div className="signin__form-wrap">
        <form className="signin__form" onSubmit={(e) => { e.preventDefault(); onSignIn(); }}>
          <h2>Welcome back</h2>
          <div className="field">
            <label htmlFor="em">Work email</label>
            <input className="input" id="em" type="email" defaultValue="maya@northwind.co" placeholder="you@company.com" />
          </div>
          <div className="field">
            <label htmlFor="pw">Password</label>
            <input className="input" id="pw" type="password" defaultValue="coaching" placeholder="••••••••" />
          </div>
          <button className="btn btn--primary btn--lg btn--block" type="submit">Sign in</button>
          <div className="divider">or</div>
          <button className="btn btn--secondary btn--block" type="button" onClick={onSignIn}>Continue with SSO</button>
          <p className="muted" style={{ fontSize: 13, textAlign: "center", margin: 0 }}>
            New here? <a href="#" style={{ color: "var(--text-link)", fontWeight: 600, textDecoration: "none" }} onClick={(e)=>{e.preventDefault();onSignIn();}}>Start your first session</a>
          </p>
        </form>
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------- Today */
function Today({ go }) {
  return (
    <>
      <div className="col-2">
        <div className="card" style={{ display: "flex", flexDirection: "column", gap: 18 }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <span className="eyebrow">Today's focus</span>
            <span className="badge badge--success"><span className="dot" />On track</span>
          </div>
          <div className="serif" style={{ fontSize: 30, lineHeight: 1.1 }}>{DATA.focus}</div>
          <p className="muted" style={{ margin: 0, fontSize: 15, lineHeight: 1.55, maxWidth: 460 }}>
            You named avoiding the 1:1 as a pattern. A 12&#8209;minute session will help you plan how you'll open it.
          </p>
          <div style={{ display: "flex", gap: 12, marginTop: 4 }}>
            <button className="btn btn--primary" onClick={() => go("coach")}>
              <Icon name="sparkles" size={18} /> Start session
            </button>
            <button className="btn btn--ghost">Swap focus</button>
          </div>
        </div>

        <div className="card card--inverse" style={{ display: "flex", flexDirection: "column", gap: 18 }}>
          <span className="eyebrow" style={{ color: "var(--ocean-200)" }}>4-week plan</span>
          <div style={{ display: "flex", alignItems: "center", gap: 18 }}>
            <Ring pct={DATA.planPct} />
            <div>
              <div style={{ fontWeight: 600, fontSize: 16, marginBottom: 4 }}>Week 3 of 4</div>
              <div style={{ fontSize: 13, color: "var(--ocean-200)" }}>2 of 3 sessions done<br />this week</div>
            </div>
          </div>
          <button className="btn btn--secondary btn--sm" style={{ alignSelf: "flex-start" }} onClick={() => go("plan")}>
            View plan <Icon name="arrow-right" size={16} />
          </button>
        </div>
      </div>

      <div className="stat-row" style={{ marginTop: 20 }}>
        <StatCard icon="clock" label="Next check-in" value="Today · 4:00 PM" sub="Career growth" />
        <StatCard icon="flame" label="Reflection streak" value="5 weeks" sub="Keep it going" />
        <StatCard icon="chart" label="Momentum" value="+12%" sub="vs. last month" />
      </div>

      <div className="card" style={{ marginTop: 20, display: "flex", gap: 16, alignItems: "flex-start" }}>
        <span className="avatar avatar--lg avatar--ring">W</span>
        <div style={{ flex: 1 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
            <span style={{ fontWeight: 600, color: "var(--text-strong)" }}>{DATA.coach.name}</span>
            <span className="badge badge--brand">Coach</span>
          </div>
          <p style={{ margin: "0 0 14px", fontSize: 15, lineHeight: 1.55, color: "var(--text-body)" }}>
            "Last week you said the 1:1 felt heavy. Want to spend 10 minutes planning how you'll open it — the first two sentences?"
          </p>
          <div style={{ display: "flex", gap: 10 }}>
            <button className="btn btn--primary btn--sm" onClick={() => go("coach")}>Reply to Wren</button>
            <button className="btn btn--ghost btn--sm">Later</button>
          </div>
        </div>
      </div>

      <div style={{ marginTop: 28, marginBottom: 12, display: "flex", alignItems: "baseline", justifyContent: "space-between" }}>
        <h3 className="serif" style={{ fontSize: 20, margin: 0 }}>Recent reflections</h3>
        <button className="btn btn--ghost btn--sm" onClick={() => go("journal")}>Open journal <Icon name="arrow-right" size={15} /></button>
      </div>
      <div className="card" style={{ padding: "8px 24px" }}>
        {DATA.reflections.map((r, i) => (
          <div className="lrow" key={i}>
            <div className="lrow__icon"><Icon name="journal" /></div>
            <div style={{ flex: 1 }}>
              <div style={{ fontWeight: 600, color: "var(--text-strong)", fontSize: 15 }}>{r.title}</div>
              <div className="muted" style={{ fontSize: 13 }}>{r.date}</div>
            </div>
            <span className="tag" style={{ cursor: "default" }}>{r.tag}</span>
            <Icon name="chevron-right" size={18} style={{ color: "var(--text-subtle)" }} />
          </div>
        ))}
      </div>
    </>
  );
}

function StatCard({ icon, label, value, sub }) {
  return (
    <div className="card" style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      <div className="lrow__icon"><Icon name={icon} /></div>
      <div>
        <div className="eyebrow" style={{ marginBottom: 4 }}>{label}</div>
        <div className="serif" style={{ fontSize: 22 }}>{value}</div>
        <div className="muted" style={{ fontSize: 13, marginTop: 2 }}>{sub}</div>
      </div>
    </div>
  );
}

function Ring({ pct, size = 84, light }) {
  const stroke = 9, r = (size - stroke) / 2, c = 2 * Math.PI * r;
  return (
    <div style={{ position: "relative", width: size, height: size, display: "grid", placeItems: "center", flex: "none" }}>
      <svg width={size} height={size} style={{ transform: "rotate(-90deg)" }}>
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={light ? "var(--surface-sunken)" : "rgba(255,255,255,0.16)"} strokeWidth={stroke} />
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={light ? "var(--primary)" : "var(--accent)"} strokeWidth={stroke}
          strokeLinecap="round" strokeDasharray={c} strokeDashoffset={c - (pct/100)*c} />
      </svg>
      <span style={{ position: "absolute", fontWeight: 700, fontSize: size*0.26, color: light ? "var(--text-strong)" : "var(--text-inverse)" }}>{pct}%</span>
    </div>
  );
}

/* --------------------------------------------------------------------- Plan */
function Plan() {
  const [week, setWeek] = React.useState("w3");
  const weeks = [
    { value: "w1", label: "Week 1" }, { value: "w2", label: "Week 2" },
    { value: "w3", label: "Week 3" }, { value: "w4", label: "Week 4" },
  ];
  return (
    <>
      <div className="card card--inverse" style={{ display: "flex", alignItems: "center", gap: 24, marginBottom: 22 }}>
        <Ring pct={DATA.planPct} size={92} />
        <div style={{ flex: 1 }}>
          <span className="eyebrow" style={{ color: "var(--ocean-200)" }}>Plan · Grow into the director conversation</span>
          <div className="serif" style={{ fontSize: 24, color: "var(--text-inverse)", margin: "6px 0 4px" }}>You're 68% through a strong month.</div>
          <div style={{ fontSize: 14, color: "var(--ocean-200)" }}>3 goals · 9 of 12 sessions complete</div>
        </div>
        <button className="btn btn--accent">Add a goal <Icon name="plus" size={16} /></button>
      </div>

      <div style={{ display: "flex", gap: 18, marginBottom: 18, borderBottom: "1px solid var(--border-subtle)" }}>
        {weeks.map((w) => (
          <button key={w.value} onClick={() => setWeek(w.value)}
            style={{ background: "none", border: "none", cursor: "pointer", padding: "11px 2px", marginBottom: -1,
              fontWeight: 600, fontSize: 14, color: week === w.value ? "var(--primary)" : "var(--text-muted)",
              borderBottom: week === w.value ? "2px solid var(--primary)" : "2px solid transparent" }}>
            {w.label}
          </button>
        ))}
      </div>

      <div className="stack" style={{ gap: 16 }}>
        {DATA.goals.map((g, i) => (
          <div className="card" key={i} style={{ display: "flex", flexDirection: "column", gap: 14 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
              <div className="lrow__icon"><Icon name="target" /></div>
              <div style={{ flex: 1 }}>
                <div style={{ fontWeight: 600, color: "var(--text-strong)", fontSize: 16 }}>{g.title}</div>
                <span className="tag tag--selected" style={{ cursor: "default", marginTop: 6 }}>{g.tag}</span>
              </div>
              <span className="badge badge--neutral">{g.pct}%</span>
            </div>
            <div className="prog-track"><div className="prog-fill" style={{ width: g.pct + "%" }} /></div>
          </div>
        ))}
      </div>

      <h3 className="serif" style={{ fontSize: 20, margin: "28px 0 12px" }}>This week's sessions</h3>
      <div className="card" style={{ padding: "8px 24px" }}>
        {DATA.sessions.map((s, i) => (
          <div className="lrow" key={i}>
            <div className="lrow__icon"><Icon name={s.icon} /></div>
            <div style={{ flex: 1 }}>
              <div style={{ fontWeight: 600, color: "var(--text-strong)", fontSize: 15 }}>{s.title}</div>
              <div className="muted" style={{ fontSize: 13 }}>{s.when}</div>
            </div>
            <button className="btn btn--secondary btn--sm">Start</button>
          </div>
        ))}
      </div>
    </>
  );
}

window.Logo = Logo;
window.SignIn = SignIn;
window.Today = Today;
window.Plan = Plan;
window.Ring = Ring;
