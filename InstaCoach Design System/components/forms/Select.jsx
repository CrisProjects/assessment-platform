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
.ic-selectfield { display: flex; flex-direction: column; gap: var(--space-2); font-family: var(--font-sans); }
.ic-selectfield__label { font-size: var(--text-sm); font-weight: var(--weight-semibold); color: var(--text-strong); }
.ic-selectwrap { position: relative; display: flex; align-items: center; }
.ic-selectwrap::after {
  content: ""; position: absolute; right: 14px; width: 9px; height: 9px;
  border-right: 1.6px solid var(--text-muted); border-bottom: 1.6px solid var(--text-muted);
  transform: translateY(-2px) rotate(45deg); pointer-events: none;
}
.ic-select {
  appearance: none; width: 100%; font-family: var(--font-sans); font-size: var(--text-body);
  color: var(--text-strong); background: var(--surface-card);
  border: 1.5px solid var(--border-default); border-radius: var(--radius-md);
  padding: 10px 38px 10px 14px; cursor: pointer;
  transition: border-color var(--dur-fast) var(--ease-out), box-shadow var(--dur-fast) var(--ease-out);
}
.ic-select:hover { border-color: var(--border-strong); }
.ic-select:focus { outline: none; border-color: var(--primary); box-shadow: var(--ring); }
.ic-select:disabled { background: var(--surface-sunken); opacity: 0.7; cursor: not-allowed; }
`;

/**
 * Native select, styled to match Input with a custom chevron.
 * Pass <option>s as children, or an `options` array of {value,label}.
 */
export function Select({ label, id, options, children, className = "", ...rest }) {
  useStyleOnce("ic-select", CSS);
  const autoId = React.useId();
  const fieldId = id || autoId;
  return (
    <div className="ic-selectfield">
      {label ? <label className="ic-selectfield__label" htmlFor={fieldId}>{label}</label> : null}
      <div className="ic-selectwrap">
        <select id={fieldId} className={`ic-select ${className}`} {...rest}>
          {options
            ? options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)
            : children}
        </select>
      </div>
    </div>
  );
}
