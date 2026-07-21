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
.ic-field { display: flex; flex-direction: column; gap: var(--space-2); font-family: var(--font-sans); }
.ic-field__label { font-size: var(--text-sm); font-weight: var(--weight-semibold); color: var(--text-strong); }
.ic-field__hint { font-size: var(--text-xs); color: var(--text-muted); }
.ic-field__error { font-size: var(--text-xs); color: var(--danger); font-weight: var(--weight-medium); }
.ic-inputwrap { position: relative; display: flex; align-items: center; }
.ic-inputwrap__icon { position: absolute; left: 12px; display: inline-flex; color: var(--text-subtle); pointer-events: none; }
.ic-input {
  width: 100%; font-family: var(--font-sans); font-size: var(--text-body);
  color: var(--text-strong); background: var(--surface-card);
  border: 1.5px solid var(--border-default); border-radius: var(--radius-md);
  padding: 10px 14px; transition: border-color var(--dur-fast) var(--ease-out),
              box-shadow var(--dur-fast) var(--ease-out);
}
.ic-input--with-icon { padding-left: 38px; }
.ic-input::placeholder { color: var(--text-subtle); }
.ic-input:hover:not(:disabled) { border-color: var(--border-strong); }
.ic-input:focus { outline: none; border-color: var(--primary); box-shadow: var(--ring); }
.ic-input:disabled { background: var(--surface-sunken); opacity: 0.7; cursor: not-allowed; }
.ic-input--error { border-color: var(--danger); }
.ic-input--error:focus { box-shadow: 0 0 0 3px var(--danger-soft); }
`;

/**
 * Labelled text input with optional leading icon, hint and error states.
 */
export function Input({
  label,
  hint,
  error,
  icon,
  id,
  className = "",
  ...rest
}) {
  useStyleOnce("ic-input", CSS);
  const autoId = React.useId();
  const fieldId = id || autoId;
  return (
    <div className="ic-field">
      {label ? <label className="ic-field__label" htmlFor={fieldId}>{label}</label> : null}
      <div className="ic-inputwrap">
        {icon ? <span className="ic-inputwrap__icon">{icon}</span> : null}
        <input
          id={fieldId}
          className={`ic-input${icon ? " ic-input--with-icon" : ""}${error ? " ic-input--error" : ""} ${className}`}
          aria-invalid={error ? true : undefined}
          {...rest}
        />
      </div>
      {error ? <span className="ic-field__error">{error}</span>
        : hint ? <span className="ic-field__hint">{hint}</span> : null}
    </div>
  );
}
