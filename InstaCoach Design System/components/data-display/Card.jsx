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
.ic-card {
  background: var(--surface-card); border: 1px solid var(--border-subtle);
  border-radius: var(--radius-lg); box-shadow: var(--shadow-sm);
  transition: box-shadow var(--dur-base) var(--ease-out),
              transform var(--dur-base) var(--ease-out),
              border-color var(--dur-base) var(--ease-out);
}
.ic-card--pad-sm { padding: var(--space-4); }
.ic-card--pad-md { padding: var(--space-6); }
.ic-card--pad-lg { padding: var(--space-8); }
.ic-card--interactive { cursor: pointer; }
.ic-card--interactive:hover { box-shadow: var(--shadow-md); transform: translateY(-2px); border-color: var(--border-brand); }
.ic-card--interactive:active { transform: translateY(0); }
.ic-card--inverse { background: var(--surface-inverse); border-color: transparent; color: var(--text-inverse); }
.ic-card--flat { box-shadow: none; }
`;

/**
 * Surface container. The workhorse layout primitive — everything in the
 * product sits on a Card. Soft shadow + hairline border on cream.
 */
export function Card({
  padding = "md",
  interactive = false,
  inverse = false,
  flat = false,
  className = "",
  children,
  ...rest
}) {
  useStyleOnce("ic-card", CSS);
  const cls = [
    "ic-card",
    `ic-card--pad-${padding}`,
    interactive ? "ic-card--interactive" : "",
    inverse ? "ic-card--inverse" : "",
    flat ? "ic-card--flat" : "",
    className,
  ].filter(Boolean).join(" ");
  return <div className={cls} {...rest}>{children}</div>;
}
