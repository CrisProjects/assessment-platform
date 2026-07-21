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
.ic-iconbtn {
  display: inline-flex; align-items: center; justify-content: center;
  border-radius: var(--radius-md); border: 1.5px solid transparent;
  background: transparent; color: var(--text-muted); cursor: pointer;
  transition: background var(--dur-fast) var(--ease-out),
              color var(--dur-fast) var(--ease-out),
              border-color var(--dur-fast) var(--ease-out),
              transform var(--dur-fast) var(--ease-out);
}
.ic-iconbtn:hover:not(:disabled) { background: var(--surface-hover); color: var(--text-strong); }
.ic-iconbtn:active:not(:disabled) { transform: scale(0.94); }
.ic-iconbtn:focus-visible { outline: none; box-shadow: var(--ring); }
.ic-iconbtn:disabled { opacity: 0.4; cursor: not-allowed; }
.ic-iconbtn--sm { width: 30px; height: 30px; }
.ic-iconbtn--md { width: 38px; height: 38px; }
.ic-iconbtn--lg { width: 44px; height: 44px; }
.ic-iconbtn--solid { background: var(--primary); color: var(--primary-contrast); }
.ic-iconbtn--solid:hover:not(:disabled) { background: var(--primary-hover); color: var(--primary-contrast); }
.ic-iconbtn--outline { border-color: var(--border-default); color: var(--text-strong); }
.ic-iconbtn--outline:hover:not(:disabled) { border-color: var(--border-brand); background: var(--surface-hover); }
`;

/**
 * Square icon-only button. Always pass `aria-label` for accessibility.
 */
export function IconButton({ variant = "plain", size = "md", children, ...rest }) {
  useStyleOnce("ic-iconbtn", CSS);
  const v = variant === "plain" ? "" : ` ic-iconbtn--${variant}`;
  return (
    <button className={`ic-iconbtn ic-iconbtn--${size}${v}`} {...rest}>
      {children}
    </button>
  );
}
