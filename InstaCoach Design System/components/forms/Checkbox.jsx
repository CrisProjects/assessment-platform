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
.ic-check { display: inline-flex; align-items: flex-start; gap: var(--space-3); cursor: pointer; font-family: var(--font-sans); }
.ic-check input { position: absolute; opacity: 0; width: 0; height: 0; }
.ic-check__box {
  flex: none; width: 20px; height: 20px; margin-top: 1px; border-radius: var(--radius-xs);
  border: 1.5px solid var(--border-strong); background: var(--surface-card);
  display: grid; place-items: center;
  transition: background var(--dur-fast) var(--ease-out), border-color var(--dur-fast) var(--ease-out);
}
.ic-check__box svg { width: 13px; height: 13px; stroke: var(--primary-contrast); stroke-width: 3; fill: none; stroke-linecap: round; stroke-linejoin: round; opacity: 0; transition: opacity var(--dur-fast) var(--ease-out); }
.ic-check:hover .ic-check__box { border-color: var(--primary); }
.ic-check input:checked + .ic-check__box { background: var(--primary); border-color: var(--primary); }
.ic-check input:checked + .ic-check__box svg { opacity: 1; }
.ic-check input:focus-visible + .ic-check__box { box-shadow: var(--ring); }
.ic-check input:disabled + .ic-check__box { opacity: 0.5; }
.ic-check__body { display: flex; flex-direction: column; gap: 2px; }
.ic-check__label { font-size: var(--text-body); color: var(--text-strong); line-height: 1.35; }
.ic-check__desc { font-size: var(--text-sm); color: var(--text-muted); }
`;

/**
 * Checkbox with optional label + description. Controlled or uncontrolled.
 */
export function Checkbox({ label, description, id, className = "", ...rest }) {
  useStyleOnce("ic-check", CSS);
  const autoId = React.useId();
  const fieldId = id || autoId;
  return (
    <label className={`ic-check ${className}`} htmlFor={fieldId}>
      <input id={fieldId} type="checkbox" {...rest} />
      <span className="ic-check__box">
        <svg viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12" /></svg>
      </span>
      {(label || description) ? (
        <span className="ic-check__body">
          {label ? <span className="ic-check__label">{label}</span> : null}
          {description ? <span className="ic-check__desc">{description}</span> : null}
        </span>
      ) : null}
    </label>
  );
}
