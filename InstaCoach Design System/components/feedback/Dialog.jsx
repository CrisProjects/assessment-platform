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
.ic-dialog__scrim {
  position: fixed; inset: 0; background: var(--surface-scrim);
  backdrop-filter: blur(2px); display: grid; place-items: center; padding: var(--space-6);
  z-index: 1000; animation: ic-dialog-fade var(--dur-base) var(--ease-out);
}
.ic-dialog {
  background: var(--surface-card); border-radius: var(--radius-xl);
  box-shadow: var(--shadow-xl); width: 100%; max-width: 460px;
  padding: var(--space-8); font-family: var(--font-sans);
  animation: ic-dialog-rise var(--dur-base) var(--ease-out);
}
.ic-dialog__title { font-family: var(--font-serif); font-weight: var(--weight-medium); font-size: var(--text-h3); color: var(--text-strong); margin: 0 0 8px; letter-spacing: var(--tracking-heading); }
.ic-dialog__desc { font-size: var(--text-body); color: var(--text-muted); line-height: var(--leading-body); margin: 0 0 var(--space-6); }
.ic-dialog__actions { display: flex; gap: var(--space-3); justify-content: flex-end; }
@keyframes ic-dialog-fade { from { opacity: 0; } to { opacity: 1; } }
@keyframes ic-dialog-rise { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: none; } }
@media (prefers-reduced-motion: reduce) { .ic-dialog, .ic-dialog__scrim { animation: none; } }
`;

/**
 * Modal dialog. Renders nothing when `open` is false. Click scrim or press
 * Escape to dismiss (calls `onClose`). Put buttons in `footer`.
 */
export function Dialog({ open, onClose, title, description, footer, children }) {
  useStyleOnce("ic-dialog", CSS);
  React.useEffect(() => {
    if (!open) return;
    const onKey = (e) => e.key === "Escape" && onClose && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="ic-dialog__scrim" onClick={onClose}>
      <div className="ic-dialog" role="dialog" aria-modal="true" onClick={(e) => e.stopPropagation()}>
        {title ? <h2 className="ic-dialog__title">{title}</h2> : null}
        {description ? <p className="ic-dialog__desc">{description}</p> : null}
        {children}
        {footer ? <div className="ic-dialog__actions">{footer}</div> : null}
      </div>
    </div>
  );
}
