import React from "react";

/* Injects a component's CSS once per document. */
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
.ic-btn {
  display: inline-flex; align-items: center; justify-content: center; gap: var(--space-2);
  font-family: var(--font-sans); font-weight: var(--weight-semibold);
  border-radius: var(--radius-md); border: 1.5px solid transparent;
  cursor: pointer; white-space: nowrap; text-decoration: none;
  transition: background var(--dur-fast) var(--ease-out),
              border-color var(--dur-fast) var(--ease-out),
              color var(--dur-fast) var(--ease-out),
              transform var(--dur-fast) var(--ease-out),
              box-shadow var(--dur-fast) var(--ease-out);
}
.ic-btn:focus-visible { outline: none; box-shadow: var(--ring); }
.ic-btn:active { transform: translateY(1px) scale(0.99); }
.ic-btn:disabled { opacity: 0.45; cursor: not-allowed; transform: none; }
.ic-btn__icon { display: inline-flex; }
.ic-btn--block { width: 100%; }

/* sizes */
.ic-btn--sm { font-size: var(--text-sm); padding: 7px 12px; }
.ic-btn--md { font-size: var(--text-body); padding: 10px 18px; }
.ic-btn--lg { font-size: var(--text-body-lg); padding: 13px 24px; }

/* variants */
.ic-btn--primary { background: var(--primary); color: var(--primary-contrast); }
.ic-btn--primary:hover:not(:disabled) { background: var(--primary-hover); }
.ic-btn--primary:active:not(:disabled) { background: var(--primary-active); }

.ic-btn--secondary { background: var(--surface-card); color: var(--text-strong); border-color: var(--border-default); box-shadow: var(--shadow-xs); }
.ic-btn--secondary:hover:not(:disabled) { background: var(--surface-hover); border-color: var(--border-brand); }

.ic-btn--ghost { background: transparent; color: var(--primary); }
.ic-btn--ghost:hover:not(:disabled) { background: var(--surface-hover); }

.ic-btn--accent { background: var(--accent); color: var(--text-on-accent); }
.ic-btn--accent:hover:not(:disabled) { background: var(--accent-hover); }

.ic-btn--danger { background: var(--danger); color: #fff; }
.ic-btn--danger:hover:not(:disabled) { filter: brightness(0.94); }
`;

/**
 * InstaCoach primary action button.
 * Variants: primary | secondary | ghost | accent | danger. Sizes: sm | md | lg.
 */
export function Button({
  variant = "primary",
  size = "md",
  leadingIcon,
  trailingIcon,
  fullWidth = false,
  disabled = false,
  as = "button",
  children,
  ...rest
}) {
  useStyleOnce("ic-button", CSS);
  const Tag = as;
  const cls = `ic-btn ic-btn--${variant} ic-btn--${size}${fullWidth ? " ic-btn--block" : ""}`;
  return (
    <Tag className={cls} disabled={Tag === "button" ? disabled : undefined} {...rest}>
      {leadingIcon ? <span className="ic-btn__icon">{leadingIcon}</span> : null}
      {children ? <span>{children}</span> : null}
      {trailingIcon ? <span className="ic-btn__icon">{trailingIcon}</span> : null}
    </Tag>
  );
}
