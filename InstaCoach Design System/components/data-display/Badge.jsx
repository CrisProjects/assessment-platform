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
.ic-badge {
  display: inline-flex; align-items: center; gap: 5px;
  font-family: var(--font-sans); font-size: var(--text-xs); font-weight: var(--weight-bold);
  letter-spacing: 0.02em; padding: 3px 9px; border-radius: var(--radius-pill);
  line-height: 1.4; white-space: nowrap;
}
.ic-badge__dot { width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
.ic-badge--neutral { background: var(--surface-sunken); color: var(--text-muted); }
.ic-badge--brand   { background: var(--primary-soft); color: var(--ocean-700); }
.ic-badge--success { background: var(--success-soft); color: var(--success); }
.ic-badge--warning { background: var(--warning-soft); color: var(--warning); }
.ic-badge--danger  { background: var(--danger-soft); color: var(--danger); }
.ic-badge--info    { background: var(--info-soft); color: var(--info); }
.ic-badge--accent  { background: var(--accent-soft); color: var(--gold-700); }
`;

/**
 * Small status pill — "On track", "Overdue", counts, labels.
 */
export function Badge({ tone = "neutral", dot = false, children, className = "", ...rest }) {
  useStyleOnce("ic-badge", CSS);
  return (
    <span className={`ic-badge ic-badge--${tone} ${className}`} {...rest}>
      {dot ? <span className="ic-badge__dot" /> : null}
      {children}
    </span>
  );
}
