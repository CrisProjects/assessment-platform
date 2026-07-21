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

const FIELD_CSS = `
.ic-field { display: flex; flex-direction: column; gap: var(--space-2); font-family: var(--font-sans); }
.ic-field__label { font-size: var(--text-sm); font-weight: var(--weight-semibold); color: var(--text-strong); }
.ic-field__hint { font-size: var(--text-xs); color: var(--text-muted); }
.ic-field__error { font-size: var(--text-xs); color: var(--danger); font-weight: var(--weight-medium); }
.ic-input {
  width: 100%; font-family: var(--font-sans); font-size: var(--text-body);
  color: var(--text-strong); background: var(--surface-card);
  border: 1.5px solid var(--border-default); border-radius: var(--radius-md);
  padding: 10px 14px; transition: border-color var(--dur-fast) var(--ease-out), box-shadow var(--dur-fast) var(--ease-out);
}
.ic-input::placeholder { color: var(--text-subtle); }
.ic-input:hover:not(:disabled) { border-color: var(--border-strong); }
.ic-input:focus { outline: none; border-color: var(--primary); box-shadow: var(--ring); }
.ic-input--error { border-color: var(--danger); }
`;

const CSS = `
.ic-textarea { resize: vertical; min-height: 84px; line-height: var(--leading-body); }
`;

/**
 * Multi-line text field — reflections, notes, journaling. Shares Input's
 * label / hint / error anatomy.
 */
export function Textarea({ label, hint, error, id, rows = 4, className = "", ...rest }) {
  useStyleOnce("ic-input", FIELD_CSS);
  useStyleOnce("ic-textarea", CSS);
  const autoId = React.useId();
  const fieldId = id || autoId;
  return (
    <div className="ic-field">
      {label ? <label className="ic-field__label" htmlFor={fieldId}>{label}</label> : null}
      <textarea
        id={fieldId}
        rows={rows}
        className={`ic-input ic-textarea${error ? " ic-input--error" : ""} ${className}`}
        aria-invalid={error ? true : undefined}
        {...rest}
      />
      {error ? <span className="ic-field__error">{error}</span>
        : hint ? <span className="ic-field__hint">{hint}</span> : null}
    </div>
  );
}
