/* InstaCoach kit — Coach chat screen. Loaded after screens.jsx. */
const CoachIcon = window.Icon;

const COACH_REPLIES = [
  "That makes sense. What's the first sentence you'd want to say — out loud, in your words?",
  "Good. Notice you led with the impact, not the blame. How does saying it that way feel in your body?",
  "Let's keep that. Before the 1:1, take two slow breaths and reread that opening line. Want me to add it to today's plan?",
  "Done — it's on your plan for 4:00 PM. You've got a clear, kind way in. That's the whole job today.",
];

function Coach() {
  const [messages, setMessages] = React.useState([
    { from: "coach", text: "Hi Maya. Last week the 1:1 felt heavy. Want to spend a few minutes planning how you'll open it?" },
    { from: "user", text: "Yeah. I keep softening it so much the point gets lost." },
    { from: "coach", text: "That's a really common pattern. If you had one clear sentence to name what you need, what would it be?" },
  ]);
  const [draft, setDraft] = React.useState("");
  const [typing, setTyping] = React.useState(false);
  const replyIdx = React.useRef(0);
  const scrollRef = React.useRef(null);

  React.useEffect(() => {
    const el = scrollRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [messages, typing]);

  const send = () => {
    const text = draft.trim();
    if (!text) return;
    setMessages((m) => [...m, { from: "user", text }]);
    setDraft("");
    setTyping(true);
    setTimeout(() => {
      setTyping(false);
      const reply = COACH_REPLIES[replyIdx.current % COACH_REPLIES.length];
      replyIdx.current += 1;
      setMessages((m) => [...m, { from: "coach", text: reply }]);
    }, 1300);
  };

  const onKey = (e) => {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(); }
  };

  return (
    <div className="chat">
      <div className="chat__scroll" ref={scrollRef}>
        <div className="chat__thread">
          {messages.map((m, i) => (
            <div className={`msg msg--${m.from}`} key={i}>
              {m.from === "coach" ? <span className="avatar avatar--sm avatar--ring" style={{ alignSelf: "flex-end" }}>W</span> : null}
              <div className="msg__bubble">{m.text}</div>
            </div>
          ))}
          {typing ? (
            <div className="msg msg--coach">
              <span className="avatar avatar--sm avatar--ring" style={{ alignSelf: "flex-end" }}>W</span>
              <div className="msg__bubble"><span className="typing"><span /><span /><span /></span></div>
            </div>
          ) : null}
        </div>
      </div>
      <div className="chat__composer">
        <div className="chat__composer-inner">
          <textarea className="chat__input" placeholder="Type your next thought…  (Enter to send)"
            value={draft} onChange={(e) => setDraft(e.target.value)} onKeyDown={onKey} rows={1} />
          <button className="send" onClick={send} disabled={!draft.trim()} aria-label="Send">
            <CoachIcon name="arrow-up" size={20} />
          </button>
        </div>
      </div>
    </div>
  );
}

window.Coach = Coach;
