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
.ic-switch { display: inline-flex; align-items: center; gap: var(--space-3); cursor: pointer; font-family: var(--font-sans); }
.ic-switch input { position: absolute; opacity: 0; width: 0; height: 0; }
.ic-switch__track {
  flex: none; width: 42px; height: 24px; border-radius: var(--radius-pill);
  background: var(--mist-400); padding: 3px; transition: background var(--dur-base) var(--ease-out);
}
.ic-switch__thumb {
  width: 18px; height: 18px; border-radius: 50%; background: var(--white);
  box-shadow: var(--shadow-sm); transform: translateX(0);
  transition: transform var(--dur-base) var(--ease-out);
}
.ic-switch input:checked + .ic-switch__track { background: var(--primary); }
.ic-switch input:checked + .ic-switch__track .ic-switch__thumb { transform: translateX(18px); }
.ic-switch input:focus-visible + .ic-switch__track { box-shadow: var(--ring); }
.ic-switch input:disabled + .ic-switch__track { opacity: 0.5; }
.ic-switch__label { font-size: var(--text-body); color: var(--text-strong); }
`;

/**
 * Toggle switch for instant on/off settings (no save needed).
 */
export function Switch({ label, id, className = "", ...rest }) {
  useStyleOnce("ic-switch", CSS);
  const autoId = React.useId();
  const fieldId = id || autoId;
  return (
    <label className={`ic-switch ${className}`} htmlFor={fieldId}>
      <input id={fieldId} type="checkbox" role="switch" {...rest} />
      <span className="ic-switch__track"><span className="ic-switch__thumb" /></span>
      {label ? <span className="ic-switch__label">{label}</span> : null}
    </label>
  );
}
