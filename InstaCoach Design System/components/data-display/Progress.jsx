import React from "react";

function useStyleOnce(id, css) {
  React.useEffect(() => {
    if (document.getElementById(id)) return;
    const el = document.createElement("style");
    el.id = id;
    el.textContent = css;
    document.head.appendChild(el);
  }, [id, css]);
}

const CSS = `
.ic-prog { font-family: var(--font-sans); }
.ic-prog__head { display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 7px; }
.ic-prog__label { font-size: var(--text-sm); font-weight: var(--weight-semibold); color: var(--text-strong); }
.ic-prog__value { font-size: var(--text-sm); color: var(--text-muted); font-variant-numeric: tabular-nums; }
.ic-prog__track { height: 8px; border-radius: var(--radius-pill); background: var(--surface-sunken); overflow: hidden; }
.ic-prog__fill { height: 100%; border-radius: var(--radius-pill); background: var(--primary); transition: width var(--dur-slow) var(--ease-out); }
.ic-prog__fill--accent { background: var(--accent); }
.ic-prog__fill--success { background: var(--success); }
.ic-ring { display: inline-grid; place-items: center; position: relative; }
.ic-ring__num { position: absolute; font-weight: var(--weight-bold); color: var(--text-strong); font-variant-numeric: tabular-nums; }
`;

/**
 * Progress indicator — linear bar (default) or radial ring.
 * `value` is 0–100.
 */
export function Progress({
  value = 0,
  variant = "bar",
  tone = "brand",
  label,
  showValue = true,
  size = 64,
  className = "",
  ...rest
}) {
  useStyleOnce("ic-progress", CSS);
  const pct = Math.max(0, Math.min(100, value));
  const toneClass =
    tone === "accent" ? "ic-prog__fill--accent" : tone === "success" ? "ic-prog__fill--success" : "";

  if (variant === "ring") {
    const stroke = Math.max(5, size * 0.1);
    const r = (size - stroke) / 2;
    const c = 2 * Math.PI * r;
    const strokeColor =
      tone === "accent" ? "var(--accent)" : tone === "success" ? "var(--success)" : "var(--primary)";
    return (
      <div className={`ic-ring ${className}`} style={{ width: size, height: size }} {...rest}>
        <svg width={size} height={size} style={{ transform: "rotate(-90deg)" }}>
          <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--surface-sunken)" strokeWidth={stroke} />
          <circle
            cx={size / 2} cy={size / 2} r={r} fill="none" stroke={strokeColor}
            strokeWidth={stroke} strokeLinecap="round"
            strokeDasharray={c} strokeDashoffset={c - (pct / 100) * c}
            style={{ transition: "stroke-dashoffset var(--dur-slow) var(--ease-out)" }}
          />
        </svg>
        {showValue ? <span className="ic-ring__num" style={{ fontSize: size * 0.26 }}>{Math.round(pct)}%</span> : null}
      </div>
    );
  }

  return (
    <div className={`ic-prog ${className}`} {...rest}>
      {(label || showValue) ? (
        <div className="ic-prog__head">
          {label ? <span className="ic-prog__label">{label}</span> : <span />}
          {showValue ? <span className="ic-prog__value">{Math.round(pct)}%</span> : null}
        </div>
      ) : null}
      <div className="ic-prog__track">
        <div className={`ic-prog__fill ${toneClass}`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}
