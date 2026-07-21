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
.ic-avatar {
  position: relative; display: inline-flex; align-items: center; justify-content: center;
  flex: none; border-radius: 50%; overflow: hidden; font-family: var(--font-sans);
  font-weight: var(--weight-semibold); color: var(--ocean-700);
  background: var(--primary-soft); user-select: none;
}
.ic-avatar img { width: 100%; height: 100%; object-fit: cover; }
.ic-avatar--sm { width: 28px; height: 28px; font-size: 11px; }
.ic-avatar--md { width: 38px; height: 38px; font-size: 14px; }
.ic-avatar--lg { width: 48px; height: 48px; font-size: 17px; }
.ic-avatar--xl { width: 64px; height: 64px; font-size: 22px; }
.ic-avatar__ring { box-shadow: 0 0 0 2px var(--surface-card), 0 0 0 3.5px var(--primary); }
.ic-avatar__status {
  position: absolute; bottom: 0; right: 0; width: 28%; height: 28%;
  border-radius: 50%; border: 2px solid var(--surface-card); background: var(--success);
}
`;

const SIZES = { sm: "sm", md: "md", lg: "lg", xl: "xl" };

/**
 * User avatar — image with initials fallback, optional ring + status dot.
 */
export function Avatar({ src, name = "", size = "md", ring = false, status = false, className = "", ...rest }) {
  useStyleOnce("ic-avatar", CSS);
  const initials = name
    .split(" ")
    .filter(Boolean)
    .slice(0, 2)
    .map((p) => p[0].toUpperCase())
    .join("");
  const cls = ["ic-avatar", `ic-avatar--${SIZES[size] || "md"}`, ring ? "ic-avatar__ring" : "", className]
    .filter(Boolean).join(" ");
  return (
    <span className={cls} {...rest}>
      {src ? <img src={src} alt={name} /> : <span>{initials || "?"}</span>}
      {status ? <span className="ic-avatar__status" /> : null}
    </span>
  );
}
