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
.ic-tabs { display: inline-flex; gap: 2px; font-family: var(--font-sans); }
.ic-tabs--underline { gap: var(--space-5); border-bottom: 1px solid var(--border-subtle); }
.ic-tabs--pill { background: var(--surface-sunken); padding: 4px; border-radius: var(--radius-pill); }
.ic-tab {
  position: relative; display: inline-flex; align-items: center; gap: 7px;
  font-size: var(--text-sm); font-weight: var(--weight-semibold); color: var(--text-muted);
  background: transparent; border: none; cursor: pointer; white-space: nowrap;
  transition: color var(--dur-fast) var(--ease-out), background var(--dur-fast) var(--ease-out);
}
.ic-tab:focus-visible { outline: none; box-shadow: var(--ring); border-radius: var(--radius-sm); }
.ic-tabs--underline .ic-tab { padding: 11px 2px; margin-bottom: -1px; border-bottom: 2px solid transparent; }
.ic-tabs--underline .ic-tab:hover { color: var(--text-strong); }
.ic-tabs--underline .ic-tab--active { color: var(--primary); border-bottom-color: var(--primary); }
.ic-tabs--pill .ic-tab { padding: 8px 16px; border-radius: var(--radius-pill); }
.ic-tabs--pill .ic-tab:hover { color: var(--text-strong); }
.ic-tabs--pill .ic-tab--active { color: var(--text-strong); background: var(--surface-card); box-shadow: var(--shadow-xs); }
.ic-tab__badge { font-size: 10px; font-weight: 700; background: var(--primary-soft); color: var(--ocean-700); border-radius: var(--radius-pill); padding: 1px 6px; }
`;

/**
 * Tab strip. Controlled via `value`/`onChange`, or uncontrolled with
 * `defaultValue`. Items: { value, label, icon?, badge? }.
 */
export function Tabs({ items = [], value, defaultValue, onChange, variant = "underline", className = "", ...rest }) {
  useStyleOnce("ic-tabs", CSS);
  const [internal, setInternal] = React.useState(defaultValue ?? items[0]?.value);
  const active = value !== undefined ? value : internal;
  const select = (v) => {
    if (value === undefined) setInternal(v);
    onChange && onChange(v);
  };
  return (
    <div className={`ic-tabs ic-tabs--${variant} ${className}`} role="tablist" {...rest}>
      {items.map((it) => (
        <button
          key={it.value}
          role="tab"
          aria-selected={active === it.value}
          className={`ic-tab${active === it.value ? " ic-tab--active" : ""}`}
          onClick={() => select(it.value)}
        >
          {it.icon ? <span style={{ display: "inline-flex" }}>{it.icon}</span> : null}
          {it.label}
          {it.badge != null ? <span className="ic-tab__badge">{it.badge}</span> : null}
        </button>
      ))}
    </div>
  );
}
