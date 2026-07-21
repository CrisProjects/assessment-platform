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
.ic-tag {
  display: inline-flex; align-items: center; gap: 6px;
  font-family: var(--font-sans); font-size: var(--text-sm); font-weight: var(--weight-medium);
  color: var(--text-body); background: var(--surface-card);
  border: 1px solid var(--border-default); border-radius: var(--radius-pill);
  padding: 5px 12px; line-height: 1.3;
  transition: background var(--dur-fast) var(--ease-out), border-color var(--dur-fast) var(--ease-out);
}
.ic-tag--selected { background: var(--primary-soft); border-color: var(--border-brand); color: var(--ocean-700); font-weight: var(--weight-semibold); }
.ic-tag--button { cursor: pointer; }
.ic-tag--button:hover { background: var(--surface-hover); border-color: var(--border-brand); }
.ic-tag__remove { display: inline-flex; cursor: pointer; opacity: 0.6; margin-right: -3px; }
.ic-tag__remove:hover { opacity: 1; }
`;

/**
 * Filter / keyword chip. Outlined by default; `selected` fills with sage.
 * Pass `onRemove` to show a dismiss affordance.
 */
export function Tag({ selected = false, onRemove, onClick, icon, children, className = "", ...rest }) {
  useStyleOnce("ic-tag", CSS);
  const isButton = !!onClick;
  const cls = [
    "ic-tag",
    selected ? "ic-tag--selected" : "",
    isButton ? "ic-tag--button" : "",
    className,
  ].filter(Boolean).join(" ");
  return (
    <span className={cls} onClick={onClick} {...rest}>
      {icon ? <span style={{ display: "inline-flex" }}>{icon}</span> : null}
      {children}
      {onRemove ? (
        <span className="ic-tag__remove" onClick={(e) => { e.stopPropagation(); onRemove(e); }} aria-label="Remove">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round"><path d="M6 6l12 12M18 6L6 18" /></svg>
        </span>
      ) : null}
    </span>
  );
}
