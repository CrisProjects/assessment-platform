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
.ic-toast {
  display: flex; align-items: flex-start; gap: var(--space-3);
  background: var(--surface-inverse); color: var(--text-inverse);
  border-radius: var(--radius-lg); box-shadow: var(--shadow-lg);
  padding: 14px 16px; font-family: var(--font-sans); min-width: 280px; max-width: 420px;
}
.ic-toast__icon { display: inline-flex; flex: none; margin-top: 1px; }
.ic-toast__icon--success { color: var(--ocean-300); }
.ic-toast__icon--danger { color: #E8A493; }
.ic-toast__icon--info { color: var(--teal-100); }
.ic-toast__body { display: flex; flex-direction: column; gap: 2px; flex: 1; }
.ic-toast__title { font-size: var(--text-sm); font-weight: var(--weight-semibold); }
.ic-toast__msg { font-size: var(--text-sm); color: var(--ocean-200); line-height: 1.4; }
.ic-toast__close { display: inline-flex; cursor: pointer; color: var(--ocean-200); background: none; border: none; padding: 2px; border-radius: var(--radius-sm); }
.ic-toast__close:hover { color: var(--text-inverse); }
`;

const ICONS = {
  success: '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>',
  danger: '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M12 8v5M12 16h.01"/></svg>',
  info: '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/></svg>',
};

/**
 * Toast notification — brief, calm confirmation on the dark surface.
 * Presentational; pair with your own queue/timer.
 */
export function Toast({ tone = "success", title, children, onClose, className = "", ...rest }) {
  useStyleOnce("ic-toast", CSS);
  return (
    <div className={`ic-toast ${className}`} role="status" {...rest}>
      <span className={`ic-toast__icon ic-toast__icon--${tone}`} dangerouslySetInnerHTML={{ __html: ICONS[tone] || ICONS.info }} />
      <div className="ic-toast__body">
        {title ? <span className="ic-toast__title">{title}</span> : null}
        {children ? <span className="ic-toast__msg">{children}</span> : null}
      </div>
      {onClose ? (
        <button className="ic-toast__close" onClick={onClose} aria-label="Dismiss">
          <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round"><path d="M6 6l12 12M18 6L6 18" /></svg>
        </button>
      ) : null}
    </div>
  );
}
