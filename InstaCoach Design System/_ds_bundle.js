/* @ds-bundle: {"format":3,"namespace":"InstaCoachDesignSystem_6bdd5c","components":[{"name":"Avatar","sourcePath":"components/data-display/Avatar.jsx"},{"name":"Badge","sourcePath":"components/data-display/Badge.jsx"},{"name":"Card","sourcePath":"components/data-display/Card.jsx"},{"name":"Progress","sourcePath":"components/data-display/Progress.jsx"},{"name":"Tag","sourcePath":"components/data-display/Tag.jsx"},{"name":"Dialog","sourcePath":"components/feedback/Dialog.jsx"},{"name":"Toast","sourcePath":"components/feedback/Toast.jsx"},{"name":"Button","sourcePath":"components/forms/Button.jsx"},{"name":"Checkbox","sourcePath":"components/forms/Checkbox.jsx"},{"name":"IconButton","sourcePath":"components/forms/IconButton.jsx"},{"name":"Input","sourcePath":"components/forms/Input.jsx"},{"name":"Select","sourcePath":"components/forms/Select.jsx"},{"name":"Switch","sourcePath":"components/forms/Switch.jsx"},{"name":"Textarea","sourcePath":"components/forms/Textarea.jsx"},{"name":"Tabs","sourcePath":"components/navigation/Tabs.jsx"}],"sourceHashes":{"components/data-display/Avatar.jsx":"0384268950ba","components/data-display/Badge.jsx":"e6d5fff720fc","components/data-display/Card.jsx":"ad36e02ffa14","components/data-display/Progress.jsx":"1dc162798ed7","components/data-display/Tag.jsx":"bb6ede76158d","components/feedback/Dialog.jsx":"b1f95ba588f9","components/feedback/Toast.jsx":"8113bfffcda6","components/forms/Button.jsx":"2a1272cd51fa","components/forms/Checkbox.jsx":"3e7ea7c6c1ea","components/forms/IconButton.jsx":"3169c2c49ca3","components/forms/Input.jsx":"14262b8f5dee","components/forms/Select.jsx":"38a9bc364288","components/forms/Switch.jsx":"63f0fa00a0aa","components/forms/Textarea.jsx":"f149078a4e42","components/navigation/Tabs.jsx":"b614e7bf8e78","design-canvas.jsx":"bd8746af6e58","ui_kits/dashboard/app.jsx":"972a20fa1863","ui_kits/dashboard/coach.jsx":"5732a71cf8ee","ui_kits/dashboard/icons.jsx":"20ac4882c56b","ui_kits/dashboard/screens.jsx":"5abdeba880a3"},"inlinedExternals":[],"unexposedExports":[]} */

(() => {

const __ds_ns = (window.InstaCoachDesignSystem_6bdd5c = window.InstaCoachDesignSystem_6bdd5c || {});

const __ds_scope = {};

(__ds_ns.__errors = __ds_ns.__errors || []);

// components/data-display/Avatar.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
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
const SIZES = {
  sm: "sm",
  md: "md",
  lg: "lg",
  xl: "xl"
};

/**
 * User avatar — image with initials fallback, optional ring + status dot.
 */
function Avatar({
  src,
  name = "",
  size = "md",
  ring = false,
  status = false,
  className = "",
  ...rest
}) {
  useStyleOnce("ic-avatar", CSS);
  const initials = name.split(" ").filter(Boolean).slice(0, 2).map(p => p[0].toUpperCase()).join("");
  const cls = ["ic-avatar", `ic-avatar--${SIZES[size] || "md"}`, ring ? "ic-avatar__ring" : "", className].filter(Boolean).join(" ");
  return /*#__PURE__*/React.createElement("span", _extends({
    className: cls
  }, rest), src ? /*#__PURE__*/React.createElement("img", {
    src: src,
    alt: name
  }) : /*#__PURE__*/React.createElement("span", null, initials || "?"), status ? /*#__PURE__*/React.createElement("span", {
    className: "ic-avatar__status"
  }) : null);
}
Object.assign(__ds_scope, { Avatar });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/data-display/Avatar.jsx", error: String((e && e.message) || e) }); }

// components/data-display/Badge.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
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
.ic-badge {
  display: inline-flex; align-items: center; gap: 5px;
  font-family: var(--font-sans); font-size: var(--text-xs); font-weight: var(--weight-bold);
  letter-spacing: 0.02em; padding: 3px 9px; border-radius: var(--radius-pill);
  line-height: 1.4; white-space: nowrap;
}
.ic-badge__dot { width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
.ic-badge--neutral { background: var(--surface-sunken); color: var(--text-muted); }
.ic-badge--brand   { background: var(--primary-soft); color: var(--ocean-700); }
.ic-badge--success { background: var(--success-soft); color: var(--success); }
.ic-badge--warning { background: var(--warning-soft); color: var(--warning); }
.ic-badge--danger  { background: var(--danger-soft); color: var(--danger); }
.ic-badge--info    { background: var(--info-soft); color: var(--info); }
.ic-badge--accent  { background: var(--accent-soft); color: var(--gold-700); }
`;

/**
 * Small status pill — "On track", "Overdue", counts, labels.
 */
function Badge({
  tone = "neutral",
  dot = false,
  children,
  className = "",
  ...rest
}) {
  useStyleOnce("ic-badge", CSS);
  return /*#__PURE__*/React.createElement("span", _extends({
    className: `ic-badge ic-badge--${tone} ${className}`
  }, rest), dot ? /*#__PURE__*/React.createElement("span", {
    className: "ic-badge__dot"
  }) : null, children);
}
Object.assign(__ds_scope, { Badge });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/data-display/Badge.jsx", error: String((e && e.message) || e) }); }

// components/data-display/Card.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
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
function Card({
  padding = "md",
  interactive = false,
  inverse = false,
  flat = false,
  className = "",
  children,
  ...rest
}) {
  useStyleOnce("ic-card", CSS);
  const cls = ["ic-card", `ic-card--pad-${padding}`, interactive ? "ic-card--interactive" : "", inverse ? "ic-card--inverse" : "", flat ? "ic-card--flat" : "", className].filter(Boolean).join(" ");
  return /*#__PURE__*/React.createElement("div", _extends({
    className: cls
  }, rest), children);
}
Object.assign(__ds_scope, { Card });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/data-display/Card.jsx", error: String((e && e.message) || e) }); }

// components/data-display/Progress.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
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
.ic-prog { font-family: var(--font-sans); }
.ic-prog__head { display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 7px; }
.ic-prog__label { font-size: var(--text-sm); font-weight: var(--weight-semibold); color: var(--text-strong); }
.ic-prog__value { font-size: var(--text-sm); color: var(--text-muted); font-variant-numeric: tabular-nums; }
.ic-prog__track { height: 8px; border-radius: var(--radius-pill); background: var(--surface-sunken); overflow: hidden; }
.ic-prog__fill { height: 100%; border-radius: var(--radius-pill); background: var(--primary); transition: width var(--dur-slow) var(--ease-out); }
.ic-prog__fill--accent { background: var(--accent); }
.ic-prog__fill--success { background: var(--success); }
.ic-ring { display: inline-grid; place-items: center; position: relative; }
.ic-ring__num { position: absolute; font-weight: var(--weight-bold); color: var(--text-strong); font-variant-numeric: tabular-nums; }
`;

/**
 * Progress indicator — linear bar (default) or radial ring.
 * `value` is 0–100.
 */
function Progress({
  value = 0,
  variant = "bar",
  tone = "brand",
  label,
  showValue = true,
  size = 64,
  className = "",
  ...rest
}) {
  useStyleOnce("ic-progress", CSS);
  const pct = Math.max(0, Math.min(100, value));
  const toneClass = tone === "accent" ? "ic-prog__fill--accent" : tone === "success" ? "ic-prog__fill--success" : "";
  if (variant === "ring") {
    const stroke = Math.max(5, size * 0.1);
    const r = (size - stroke) / 2;
    const c = 2 * Math.PI * r;
    const strokeColor = tone === "accent" ? "var(--accent)" : tone === "success" ? "var(--success)" : "var(--primary)";
    return /*#__PURE__*/React.createElement("div", _extends({
      className: `ic-ring ${className}`,
      style: {
        width: size,
        height: size
      }
    }, rest), /*#__PURE__*/React.createElement("svg", {
      width: size,
      height: size,
      style: {
        transform: "rotate(-90deg)"
      }
    }, /*#__PURE__*/React.createElement("circle", {
      cx: size / 2,
      cy: size / 2,
      r: r,
      fill: "none",
      stroke: "var(--surface-sunken)",
      strokeWidth: stroke
    }), /*#__PURE__*/React.createElement("circle", {
      cx: size / 2,
      cy: size / 2,
      r: r,
      fill: "none",
      stroke: strokeColor,
      strokeWidth: stroke,
      strokeLinecap: "round",
      strokeDasharray: c,
      strokeDashoffset: c - pct / 100 * c,
      style: {
        transition: "stroke-dashoffset var(--dur-slow) var(--ease-out)"
      }
    })), showValue ? /*#__PURE__*/React.createElement("span", {
      className: "ic-ring__num",
      style: {
        fontSize: size * 0.26
      }
    }, Math.round(pct), "%") : null);
  }
  return /*#__PURE__*/React.createElement("div", _extends({
    className: `ic-prog ${className}`
  }, rest), label || showValue ? /*#__PURE__*/React.createElement("div", {
    className: "ic-prog__head"
  }, label ? /*#__PURE__*/React.createElement("span", {
    className: "ic-prog__label"
  }, label) : /*#__PURE__*/React.createElement("span", null), showValue ? /*#__PURE__*/React.createElement("span", {
    className: "ic-prog__value"
  }, Math.round(pct), "%") : null) : null, /*#__PURE__*/React.createElement("div", {
    className: "ic-prog__track"
  }, /*#__PURE__*/React.createElement("div", {
    className: `ic-prog__fill ${toneClass}`,
    style: {
      width: `${pct}%`
    }
  })));
}
Object.assign(__ds_scope, { Progress });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/data-display/Progress.jsx", error: String((e && e.message) || e) }); }

// components/data-display/Tag.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
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
.ic-tag {
  display: inline-flex; align-items: center; gap: 6px;
  font-family: var(--font-sans); font-size: var(--text-sm); font-weight: var(--weight-medium);
  color: var(--text-body); background: var(--surface-card);
  border: 1px solid var(--border-default); border-radius: var(--radius-pill);
  padding: 5px 12px; line-height: 1.3;
  transition: background var(--dur-fast) var(--ease-out), border-color var(--dur-fast) var(--ease-out);
}
.ic-tag--selected { background: var(--primary-soft); border-color: var(--border-brand); color: var(--ocean-700); font-weight: var(--weight-semibold); }
.ic-tag--button { cursor: pointer; }
.ic-tag--button:hover { background: var(--surface-hover); border-color: var(--border-brand); }
.ic-tag__remove { display: inline-flex; cursor: pointer; opacity: 0.6; margin-right: -3px; }
.ic-tag__remove:hover { opacity: 1; }
`;

/**
 * Filter / keyword chip. Outlined by default; `selected` fills with sage.
 * Pass `onRemove` to show a dismiss affordance.
 */
function Tag({
  selected = false,
  onRemove,
  onClick,
  icon,
  children,
  className = "",
  ...rest
}) {
  useStyleOnce("ic-tag", CSS);
  const isButton = !!onClick;
  const cls = ["ic-tag", selected ? "ic-tag--selected" : "", isButton ? "ic-tag--button" : "", className].filter(Boolean).join(" ");
  return /*#__PURE__*/React.createElement("span", _extends({
    className: cls,
    onClick: onClick
  }, rest), icon ? /*#__PURE__*/React.createElement("span", {
    style: {
      display: "inline-flex"
    }
  }, icon) : null, children, onRemove ? /*#__PURE__*/React.createElement("span", {
    className: "ic-tag__remove",
    onClick: e => {
      e.stopPropagation();
      onRemove(e);
    },
    "aria-label": "Remove"
  }, /*#__PURE__*/React.createElement("svg", {
    width: "12",
    height: "12",
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "2.4",
    strokeLinecap: "round"
  }, /*#__PURE__*/React.createElement("path", {
    d: "M6 6l12 12M18 6L6 18"
  }))) : null);
}
Object.assign(__ds_scope, { Tag });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/data-display/Tag.jsx", error: String((e && e.message) || e) }); }

// components/feedback/Dialog.jsx
try { (() => {
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
.ic-dialog__scrim {
  position: fixed; inset: 0; background: var(--surface-scrim);
  backdrop-filter: blur(2px); display: grid; place-items: center; padding: var(--space-6);
  z-index: 1000; animation: ic-dialog-fade var(--dur-base) var(--ease-out);
}
.ic-dialog {
  background: var(--surface-card); border-radius: var(--radius-xl);
  box-shadow: var(--shadow-xl); width: 100%; max-width: 460px;
  padding: var(--space-8); font-family: var(--font-sans);
  animation: ic-dialog-rise var(--dur-base) var(--ease-out);
}
.ic-dialog__title { font-family: var(--font-serif); font-weight: var(--weight-medium); font-size: var(--text-h3); color: var(--text-strong); margin: 0 0 8px; letter-spacing: var(--tracking-heading); }
.ic-dialog__desc { font-size: var(--text-body); color: var(--text-muted); line-height: var(--leading-body); margin: 0 0 var(--space-6); }
.ic-dialog__actions { display: flex; gap: var(--space-3); justify-content: flex-end; }
@keyframes ic-dialog-fade { from { opacity: 0; } to { opacity: 1; } }
@keyframes ic-dialog-rise { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: none; } }
@media (prefers-reduced-motion: reduce) { .ic-dialog, .ic-dialog__scrim { animation: none; } }
`;

/**
 * Modal dialog. Renders nothing when `open` is false. Click scrim or press
 * Escape to dismiss (calls `onClose`). Put buttons in `footer`.
 */
function Dialog({
  open,
  onClose,
  title,
  description,
  footer,
  children
}) {
  useStyleOnce("ic-dialog", CSS);
  React.useEffect(() => {
    if (!open) return;
    const onKey = e => e.key === "Escape" && onClose && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);
  if (!open) return null;
  return /*#__PURE__*/React.createElement("div", {
    className: "ic-dialog__scrim",
    onClick: onClose
  }, /*#__PURE__*/React.createElement("div", {
    className: "ic-dialog",
    role: "dialog",
    "aria-modal": "true",
    onClick: e => e.stopPropagation()
  }, title ? /*#__PURE__*/React.createElement("h2", {
    className: "ic-dialog__title"
  }, title) : null, description ? /*#__PURE__*/React.createElement("p", {
    className: "ic-dialog__desc"
  }, description) : null, children, footer ? /*#__PURE__*/React.createElement("div", {
    className: "ic-dialog__actions"
  }, footer) : null));
}
Object.assign(__ds_scope, { Dialog });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/feedback/Dialog.jsx", error: String((e && e.message) || e) }); }

// components/feedback/Toast.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
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
.ic-toast {
  display: flex; align-items: flex-start; gap: var(--space-3);
  background: var(--surface-inverse); color: var(--text-inverse);
  border-radius: var(--radius-lg); box-shadow: var(--shadow-lg);
  padding: 14px 16px; font-family: var(--font-sans); min-width: 280px; max-width: 420px;
}
.ic-toast__icon { display: inline-flex; flex: none; margin-top: 1px; }
.ic-toast__icon--success { color: var(--ocean-300); }
.ic-toast__icon--danger { color: #E8A493; }
.ic-toast__icon--info { color: var(--teal-100); }
.ic-toast__body { display: flex; flex-direction: column; gap: 2px; flex: 1; }
.ic-toast__title { font-size: var(--text-sm); font-weight: var(--weight-semibold); }
.ic-toast__msg { font-size: var(--text-sm); color: var(--ocean-200); line-height: 1.4; }
.ic-toast__close { display: inline-flex; cursor: pointer; color: var(--ocean-200); background: none; border: none; padding: 2px; border-radius: var(--radius-sm); }
.ic-toast__close:hover { color: var(--text-inverse); }
`;
const ICONS = {
  success: '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>',
  danger: '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M12 8v5M12 16h.01"/></svg>',
  info: '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/></svg>'
};

/**
 * Toast notification — brief, calm confirmation on the dark surface.
 * Presentational; pair with your own queue/timer.
 */
function Toast({
  tone = "success",
  title,
  children,
  onClose,
  className = "",
  ...rest
}) {
  useStyleOnce("ic-toast", CSS);
  return /*#__PURE__*/React.createElement("div", _extends({
    className: `ic-toast ${className}`,
    role: "status"
  }, rest), /*#__PURE__*/React.createElement("span", {
    className: `ic-toast__icon ic-toast__icon--${tone}`,
    dangerouslySetInnerHTML: {
      __html: ICONS[tone] || ICONS.info
    }
  }), /*#__PURE__*/React.createElement("div", {
    className: "ic-toast__body"
  }, title ? /*#__PURE__*/React.createElement("span", {
    className: "ic-toast__title"
  }, title) : null, children ? /*#__PURE__*/React.createElement("span", {
    className: "ic-toast__msg"
  }, children) : null), onClose ? /*#__PURE__*/React.createElement("button", {
    className: "ic-toast__close",
    onClick: onClose,
    "aria-label": "Dismiss"
  }, /*#__PURE__*/React.createElement("svg", {
    viewBox: "0 0 24 24",
    width: "15",
    height: "15",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "2.2",
    strokeLinecap: "round"
  }, /*#__PURE__*/React.createElement("path", {
    d: "M6 6l12 12M18 6L6 18"
  }))) : null);
}
Object.assign(__ds_scope, { Toast });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/feedback/Toast.jsx", error: String((e && e.message) || e) }); }

// components/forms/Button.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
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
function Button({
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
  return /*#__PURE__*/React.createElement(Tag, _extends({
    className: cls,
    disabled: Tag === "button" ? disabled : undefined
  }, rest), leadingIcon ? /*#__PURE__*/React.createElement("span", {
    className: "ic-btn__icon"
  }, leadingIcon) : null, children ? /*#__PURE__*/React.createElement("span", null, children) : null, trailingIcon ? /*#__PURE__*/React.createElement("span", {
    className: "ic-btn__icon"
  }, trailingIcon) : null);
}
Object.assign(__ds_scope, { Button });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/forms/Button.jsx", error: String((e && e.message) || e) }); }

// components/forms/Checkbox.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
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
function Checkbox({
  label,
  description,
  id,
  className = "",
  ...rest
}) {
  useStyleOnce("ic-check", CSS);
  const autoId = React.useId();
  const fieldId = id || autoId;
  return /*#__PURE__*/React.createElement("label", {
    className: `ic-check ${className}`,
    htmlFor: fieldId
  }, /*#__PURE__*/React.createElement("input", _extends({
    id: fieldId,
    type: "checkbox"
  }, rest)), /*#__PURE__*/React.createElement("span", {
    className: "ic-check__box"
  }, /*#__PURE__*/React.createElement("svg", {
    viewBox: "0 0 24 24"
  }, /*#__PURE__*/React.createElement("polyline", {
    points: "20 6 9 17 4 12"
  }))), label || description ? /*#__PURE__*/React.createElement("span", {
    className: "ic-check__body"
  }, label ? /*#__PURE__*/React.createElement("span", {
    className: "ic-check__label"
  }, label) : null, description ? /*#__PURE__*/React.createElement("span", {
    className: "ic-check__desc"
  }, description) : null) : null);
}
Object.assign(__ds_scope, { Checkbox });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/forms/Checkbox.jsx", error: String((e && e.message) || e) }); }

// components/forms/IconButton.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
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
function IconButton({
  variant = "plain",
  size = "md",
  children,
  ...rest
}) {
  useStyleOnce("ic-iconbtn", CSS);
  const v = variant === "plain" ? "" : ` ic-iconbtn--${variant}`;
  return /*#__PURE__*/React.createElement("button", _extends({
    className: `ic-iconbtn ic-iconbtn--${size}${v}`
  }, rest), children);
}
Object.assign(__ds_scope, { IconButton });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/forms/IconButton.jsx", error: String((e && e.message) || e) }); }

// components/forms/Input.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
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
function Input({
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
  return /*#__PURE__*/React.createElement("div", {
    className: "ic-field"
  }, label ? /*#__PURE__*/React.createElement("label", {
    className: "ic-field__label",
    htmlFor: fieldId
  }, label) : null, /*#__PURE__*/React.createElement("div", {
    className: "ic-inputwrap"
  }, icon ? /*#__PURE__*/React.createElement("span", {
    className: "ic-inputwrap__icon"
  }, icon) : null, /*#__PURE__*/React.createElement("input", _extends({
    id: fieldId,
    className: `ic-input${icon ? " ic-input--with-icon" : ""}${error ? " ic-input--error" : ""} ${className}`,
    "aria-invalid": error ? true : undefined
  }, rest))), error ? /*#__PURE__*/React.createElement("span", {
    className: "ic-field__error"
  }, error) : hint ? /*#__PURE__*/React.createElement("span", {
    className: "ic-field__hint"
  }, hint) : null);
}
Object.assign(__ds_scope, { Input });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/forms/Input.jsx", error: String((e && e.message) || e) }); }

// components/forms/Select.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
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
function Select({
  label,
  id,
  options,
  children,
  className = "",
  ...rest
}) {
  useStyleOnce("ic-select", CSS);
  const autoId = React.useId();
  const fieldId = id || autoId;
  return /*#__PURE__*/React.createElement("div", {
    className: "ic-selectfield"
  }, label ? /*#__PURE__*/React.createElement("label", {
    className: "ic-selectfield__label",
    htmlFor: fieldId
  }, label) : null, /*#__PURE__*/React.createElement("div", {
    className: "ic-selectwrap"
  }, /*#__PURE__*/React.createElement("select", _extends({
    id: fieldId,
    className: `ic-select ${className}`
  }, rest), options ? options.map(o => /*#__PURE__*/React.createElement("option", {
    key: o.value,
    value: o.value
  }, o.label)) : children)));
}
Object.assign(__ds_scope, { Select });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/forms/Select.jsx", error: String((e && e.message) || e) }); }

// components/forms/Switch.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
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
function Switch({
  label,
  id,
  className = "",
  ...rest
}) {
  useStyleOnce("ic-switch", CSS);
  const autoId = React.useId();
  const fieldId = id || autoId;
  return /*#__PURE__*/React.createElement("label", {
    className: `ic-switch ${className}`,
    htmlFor: fieldId
  }, /*#__PURE__*/React.createElement("input", _extends({
    id: fieldId,
    type: "checkbox",
    role: "switch"
  }, rest)), /*#__PURE__*/React.createElement("span", {
    className: "ic-switch__track"
  }, /*#__PURE__*/React.createElement("span", {
    className: "ic-switch__thumb"
  })), label ? /*#__PURE__*/React.createElement("span", {
    className: "ic-switch__label"
  }, label) : null);
}
Object.assign(__ds_scope, { Switch });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/forms/Switch.jsx", error: String((e && e.message) || e) }); }

// components/forms/Textarea.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
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
function Textarea({
  label,
  hint,
  error,
  id,
  rows = 4,
  className = "",
  ...rest
}) {
  useStyleOnce("ic-input", FIELD_CSS);
  useStyleOnce("ic-textarea", CSS);
  const autoId = React.useId();
  const fieldId = id || autoId;
  return /*#__PURE__*/React.createElement("div", {
    className: "ic-field"
  }, label ? /*#__PURE__*/React.createElement("label", {
    className: "ic-field__label",
    htmlFor: fieldId
  }, label) : null, /*#__PURE__*/React.createElement("textarea", _extends({
    id: fieldId,
    rows: rows,
    className: `ic-input ic-textarea${error ? " ic-input--error" : ""} ${className}`,
    "aria-invalid": error ? true : undefined
  }, rest)), error ? /*#__PURE__*/React.createElement("span", {
    className: "ic-field__error"
  }, error) : hint ? /*#__PURE__*/React.createElement("span", {
    className: "ic-field__hint"
  }, hint) : null);
}
Object.assign(__ds_scope, { Textarea });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/forms/Textarea.jsx", error: String((e && e.message) || e) }); }

// components/navigation/Tabs.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
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
function Tabs({
  items = [],
  value,
  defaultValue,
  onChange,
  variant = "underline",
  className = "",
  ...rest
}) {
  useStyleOnce("ic-tabs", CSS);
  const [internal, setInternal] = React.useState(defaultValue ?? items[0]?.value);
  const active = value !== undefined ? value : internal;
  const select = v => {
    if (value === undefined) setInternal(v);
    onChange && onChange(v);
  };
  return /*#__PURE__*/React.createElement("div", _extends({
    className: `ic-tabs ic-tabs--${variant} ${className}`,
    role: "tablist"
  }, rest), items.map(it => /*#__PURE__*/React.createElement("button", {
    key: it.value,
    role: "tab",
    "aria-selected": active === it.value,
    className: `ic-tab${active === it.value ? " ic-tab--active" : ""}`,
    onClick: () => select(it.value)
  }, it.icon ? /*#__PURE__*/React.createElement("span", {
    style: {
      display: "inline-flex"
    }
  }, it.icon) : null, it.label, it.badge != null ? /*#__PURE__*/React.createElement("span", {
    className: "ic-tab__badge"
  }, it.badge) : null)));
}
Object.assign(__ds_scope, { Tabs });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/navigation/Tabs.jsx", error: String((e && e.message) || e) }); }

// design-canvas.jsx
try { (() => {
// @ds-adherence-ignore -- omelette starter scaffold (raw elements/hex/px by design)

/* BEGIN USAGE */
// DesignCanvas.jsx — Figma-ish design canvas wrapper
// Warm gray grid bg + Sections + Artboards + PostIt notes.
// Exports (to window): DesignCanvas, DCSection, DCArtboard, DCPostIt.
// Artboards are reorderable (grip-drag), deletable, labels/titles are
// inline-editable, and any artboard can be opened in a fullscreen focus
// overlay (←/→/Esc). State persists to a .design-canvas.state.json sidecar
// via the host bridge. No assets, no deps.
//
// Usage:
//   <DesignCanvas>
//     <DCSection id="onboarding" title="Onboarding" subtitle="First-run variants">
//       <DCArtboard id="a" label="A · Dusk" width={260} height={480}>…</DCArtboard>
//       <DCArtboard id="b" label="B · Minimal" width={260} height={480}>…</DCArtboard>
//     </DCSection>
//   </DesignCanvas>
//
// Artboards are static design frames, not scroll regions — never use
// height: 100% + overflow: auto/scroll on inner elements; size each artboard
// to fit its content (explicit pixel height, or let it grow).
/* END USAGE */

const DC = {
  bg: '#f0eee9',
  grid: 'rgba(0,0,0,0.06)',
  label: 'rgba(60,50,40,0.7)',
  title: 'rgba(40,30,20,0.85)',
  subtitle: 'rgba(60,50,40,0.6)',
  postitBg: '#fef4a8',
  postitText: '#5a4a2a',
  font: '-apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif'
};

// One-time CSS injection (classes are dc-prefixed so they don't collide with
// the hosted design's own styles).
if (typeof document !== 'undefined' && !document.getElementById('dc-styles')) {
  const s = document.createElement('style');
  s.id = 'dc-styles';
  s.textContent = ['.dc-editable{cursor:text;outline:none;white-space:nowrap;border-radius:3px;padding:0 2px;margin:0 -2px}', '.dc-editable:focus{background:#fff;box-shadow:0 0 0 1.5px #c96442}', '[data-dc-slot]{transition:transform .18s cubic-bezier(.2,.7,.3,1)}', '[data-dc-slot].dc-dragging{transition:none;z-index:10;pointer-events:none}', '[data-dc-slot].dc-dragging .dc-card{box-shadow:0 12px 40px rgba(0,0,0,.25),0 0 0 2px #c96442;transform:scale(1.02)}',
  // isolation:isolate contains artboard content's z-indexes so a
  // z-indexed child (sticky navbar etc.) can't paint over .dc-header or
  // the .dc-menu popover that drops into the top of the card.
  '.dc-card{isolation:isolate;transition:box-shadow .15s,transform .15s}', '.dc-card *{scrollbar-width:none}', '.dc-card *::-webkit-scrollbar{display:none}',
  // Per-artboard header: grip + label on the left, delete/expand on the
  // right. Single flex row; when the artboard's on-screen width is too
  // narrow for both the label yields (ellipsis, then hidden entirely below
  // ~4ch via the container query) and the buttons stay on the row.
  '.dc-header{position:absolute;bottom:100%;left:-4px;margin-bottom:calc(4px * var(--dc-inv-zoom,1));z-index:2;', '  display:flex;align-items:center;container-type:inline-size}', '.dc-labelrow{display:flex;align-items:center;gap:4px;height:24px;flex:1 1 auto;min-width:0}', '.dc-grip{flex:0 0 auto;cursor:grab;display:flex;align-items:center;padding:5px 4px;border-radius:4px;transition:background .12s,opacity .12s}', '.dc-grip:hover{background:rgba(0,0,0,.08)}', '.dc-grip:active{cursor:grabbing}', '.dc-labeltext{flex:1 1 auto;min-width:0;cursor:pointer;border-radius:4px;padding:3px 6px;', '  display:flex;align-items:center;transition:background .12s;overflow:hidden}',
  // Below ~4ch of label room: hide the label entirely, and drop the grip to
  // hover-only (same reveal rule as .dc-btns) so a narrow header is clean
  // until the card is moused.
  '@container (max-width: 110px){', '  .dc-labeltext{display:none}', '  .dc-grip{opacity:0}', '  [data-dc-slot]:hover .dc-grip{opacity:1}', '}', '.dc-labeltext:hover{background:rgba(0,0,0,.05)}', '.dc-labeltext .dc-editable{overflow:hidden;text-overflow:ellipsis;max-width:100%}', '.dc-labeltext .dc-editable:focus{overflow:visible;text-overflow:clip}', '.dc-btns{flex:0 0 auto;margin-left:auto;display:flex;gap:2px;opacity:0;transition:opacity .12s}', '[data-dc-slot]:hover .dc-btns,.dc-btns:has(.dc-menu){opacity:1}', '.dc-expand,.dc-kebab{width:22px;height:22px;border-radius:5px;border:none;cursor:pointer;padding:0;', '  background:transparent;color:rgba(60,50,40,.7);display:flex;align-items:center;justify-content:center;', '  font:inherit;transition:background .12s,color .12s}', '.dc-expand:hover,.dc-kebab:hover{background:rgba(0,0,0,.06);color:#2a251f}',
  // Slot hosting an open menu floats above later siblings (which otherwise
  // paint on top — same z-index:auto, later DOM order) so the popup isn't
  // clipped by the next card.
  '[data-dc-slot]:has(.dc-menu){z-index:10}', '.dc-menu{position:absolute;top:100%;right:0;margin-top:4px;background:#fff;border-radius:8px;', '  box-shadow:0 8px 28px rgba(0,0,0,.18),0 0 0 1px rgba(0,0,0,.05);padding:4px;min-width:160px;z-index:10}', '.dc-menu button{display:block;width:100%;padding:7px 10px;border:0;background:transparent;', '  border-radius:5px;font-family:inherit;font-size:13px;font-weight:500;line-height:1.2;', '  color:#29261b;cursor:pointer;text-align:left;transition:background .12s;white-space:nowrap}', '.dc-menu button:hover{background:rgba(0,0,0,.05)}', '.dc-menu hr{border:0;border-top:1px solid rgba(0,0,0,.08);margin:4px 2px}', '.dc-menu .dc-danger{color:#c96442}', '.dc-menu .dc-danger:hover{background:rgba(201,100,66,.1)}',
  // Chrome (titles / labels / buttons) counter-scales against the viewport
  // zoom so it stays a constant on-screen size. --dc-inv-zoom is set by
  // DCViewport on every transform update and inherits to all descendants —
  // any overlay inside the world (e.g. a TweaksPanel on an artboard) can use
  // it the same way.
  //
  // The header uses transform:scale (out-of-flow, so layout impact doesn't
  // matter) with its world-space width set to card-width / inv-zoom so that
  // after counter-scaling its on-screen width exactly matches the card's —
  // that's what lets the container query + text-overflow behave against the
  // card's visible edge at every zoom level.
  //
  // The section head uses CSS zoom instead of transform so its layout box
  // grows with the counter-scale, pushing the card row down — otherwise the
  // constant-screen-size title would overflow into the (shrinking) world-
  // space gap and overlap the artboard headers at low zoom.
  '.dc-header{width:calc((100% + 4px) / var(--dc-inv-zoom,1));', '  transform:scale(var(--dc-inv-zoom,1));transform-origin:bottom left}', '.dc-sectionhead{zoom:var(--dc-inv-zoom,1)}'].join('\n');
  document.head.appendChild(s);
}
const DCCtx = React.createContext(null);

// Recursively unwrap React.Fragment so <>…</> grouping doesn't hide
// DCSection/DCArtboard children from the type-based walks below.
function dcFlatten(children) {
  const out = [];
  React.Children.forEach(children, c => {
    if (c && c.type === React.Fragment) out.push(...dcFlatten(c.props.children));else out.push(c);
  });
  return out;
}

// ─────────────────────────────────────────────────────────────
// DesignCanvas — stateful wrapper around the pan/zoom viewport.
// Owns runtime state (per-section order, renamed titles/labels, hidden
// artboards, focused artboard). Order/titles/labels/hidden persist to a
// .design-canvas.state.json
// sidecar next to the HTML. Reads go via plain fetch() so the saved
// arrangement is visible anywhere the HTML + sidecar are served together
// (omelette preview, direct link, downloaded zip). Writes go through the
// host's window.omelette bridge — editing requires the omelette runtime.
// Focus is ephemeral.
// ─────────────────────────────────────────────────────────────
const DC_STATE_FILE = '.design-canvas.state.json';
function DesignCanvas({
  children,
  minScale,
  maxScale,
  style
}) {
  const [state, setState] = React.useState({
    sections: {},
    focus: null
  });
  // Hold rendering until the sidecar read settles so the saved order/titles
  // appear on first paint (no source-order flash). didRead gates writes until
  // the read settles so the empty initial state can't clobber a slow read;
  // skipNextWrite suppresses the one echo-write that would otherwise follow
  // hydration.
  const [ready, setReady] = React.useState(false);
  const didRead = React.useRef(false);
  const skipNextWrite = React.useRef(false);
  React.useEffect(() => {
    let off = false;
    fetch('./' + DC_STATE_FILE).then(r => r.ok ? r.json() : null).then(saved => {
      if (off || !saved || !saved.sections) return;
      skipNextWrite.current = true;
      setState(s => ({
        ...s,
        sections: saved.sections
      }));
    }).catch(() => {}).finally(() => {
      didRead.current = true;
      if (!off) setReady(true);
    });
    const t = setTimeout(() => {
      if (!off) setReady(true);
    }, 150);
    return () => {
      off = true;
      clearTimeout(t);
    };
  }, []);
  React.useEffect(() => {
    if (!didRead.current) return;
    if (skipNextWrite.current) {
      skipNextWrite.current = false;
      return;
    }
    const t = setTimeout(() => {
      window.omelette?.writeFile(DC_STATE_FILE, JSON.stringify({
        sections: state.sections
      })).catch(() => {});
    }, 250);
    return () => clearTimeout(t);
  }, [state.sections]);

  // Build registries synchronously from children so FocusOverlay can read
  // them in the same render. Fragments are flattened; wrapping in other
  // elements still opts out of focus/reorder.
  const registry = {}; // slotId -> { sectionId, artboard }
  const sectionMeta = {}; // sectionId -> { title, subtitle, slotIds[] }
  const sectionOrder = [];
  dcFlatten(children).forEach(sec => {
    if (!sec || sec.type !== DCSection) return;
    const sid = sec.props.id ?? sec.props.title;
    if (!sid) return;
    sectionOrder.push(sid);
    const persisted = state.sections[sid] || {};
    const abs = [];
    dcFlatten(sec.props.children).forEach(ab => {
      if (!ab || ab.type !== DCArtboard) return;
      const aid = ab.props.id ?? ab.props.label;
      if (aid) abs.push([aid, ab]);
    });
    // hidden is scoped to one source revision — when the agent regenerates
    // (artboard-ID set changes), prior deletes don't apply to new content.
    const srcKey = abs.map(([k]) => k).join('\x1f');
    const hidden = persisted.srcKey === srcKey ? persisted.hidden || [] : [];
    const srcIds = [];
    abs.forEach(([aid, ab]) => {
      if (hidden.includes(aid)) return;
      registry[`${sid}/${aid}`] = {
        sectionId: sid,
        artboard: ab
      };
      srcIds.push(aid);
    });
    const kept = (persisted.order || []).filter(k => srcIds.includes(k));
    sectionMeta[sid] = {
      title: persisted.title ?? sec.props.title,
      subtitle: sec.props.subtitle,
      slotIds: [...kept, ...srcIds.filter(k => !kept.includes(k))]
    };
  });
  const api = React.useMemo(() => ({
    state,
    section: id => state.sections[id] || {},
    patchSection: (id, p) => setState(s => ({
      ...s,
      sections: {
        ...s.sections,
        [id]: {
          ...s.sections[id],
          ...(typeof p === 'function' ? p(s.sections[id] || {}) : p)
        }
      }
    })),
    setFocus: slotId => setState(s => ({
      ...s,
      focus: slotId
    }))
  }), [state]);

  // Esc exits focus; any outside pointerdown commits an in-progress rename.
  React.useEffect(() => {
    const onKey = e => {
      if (e.key === 'Escape') api.setFocus(null);
    };
    const onPd = e => {
      const ae = document.activeElement;
      if (ae && ae.isContentEditable && !ae.contains(e.target)) ae.blur();
    };
    document.addEventListener('keydown', onKey);
    document.addEventListener('pointerdown', onPd, true);
    return () => {
      document.removeEventListener('keydown', onKey);
      document.removeEventListener('pointerdown', onPd, true);
    };
  }, [api]);
  return /*#__PURE__*/React.createElement(DCCtx.Provider, {
    value: api
  }, /*#__PURE__*/React.createElement(DCViewport, {
    minScale: minScale,
    maxScale: maxScale,
    style: style
  }, ready && children), state.focus && registry[state.focus] && /*#__PURE__*/React.createElement(DCFocusOverlay, {
    entry: registry[state.focus],
    sectionMeta: sectionMeta,
    sectionOrder: sectionOrder
  }));
}

// ─────────────────────────────────────────────────────────────
// DCViewport — transform-based pan/zoom (internal)
//
// Input mapping (Figma-style):
//   • trackpad pinch  → zoom   (ctrlKey wheel; Safari gesture* events)
//   • trackpad scroll → pan    (two-finger)
//   • mouse wheel     → zoom   (notched; distinguished from trackpad scroll)
//   • middle-drag / primary-drag-on-bg → pan
//
// Transform state lives in a ref and is written straight to the DOM
// (translate3d + will-change) so wheel ticks don't go through React —
// keeps pans at 60fps on dense canvases.
// ─────────────────────────────────────────────────────────────
function DCViewport({
  children,
  minScale = 0.1,
  maxScale = 8,
  style = {}
}) {
  const vpRef = React.useRef(null);
  const worldRef = React.useRef(null);
  const tf = React.useRef({
    x: 0,
    y: 0,
    scale: 1
  });
  // Persist viewport across reloads so the user lands back where they were
  // after an agent edit or browser refresh. The sandbox origin is already
  // per-project; pathname keeps multiple canvas files in one project apart.
  const tfKey = 'dc-viewport:' + location.pathname;
  const saveT = React.useRef(0);
  const lastPostedScale = React.useRef();
  const apply = React.useCallback(() => {
    const {
      x,
      y,
      scale
    } = tf.current;
    const el = worldRef.current;
    if (!el) return;
    el.style.transform = `translate3d(${x}px, ${y}px, 0) scale(${scale})`;
    // Exposed for zoom-invariant chrome (labels, buttons, TweaksPanel).
    el.style.setProperty('--dc-inv-zoom', String(1 / scale));
    // Keep the host toolbar's % readout in sync with the canvas scale. Pan
    // ticks leave scale unchanged — skip the cross-frame post for those.
    if (lastPostedScale.current !== scale) {
      lastPostedScale.current = scale;
      window.parent.postMessage({
        type: '__dc_zoom',
        scale
      }, '*');
    }
    clearTimeout(saveT.current);
    saveT.current = setTimeout(() => {
      try {
        localStorage.setItem(tfKey, JSON.stringify(tf.current));
      } catch {}
    }, 200);
  }, [tfKey]);
  React.useLayoutEffect(() => {
    const flush = () => {
      clearTimeout(saveT.current);
      try {
        localStorage.setItem(tfKey, JSON.stringify(tf.current));
      } catch {}
    };
    try {
      const s = JSON.parse(localStorage.getItem(tfKey) || 'null');
      if (s && Number.isFinite(s.x) && Number.isFinite(s.y) && Number.isFinite(s.scale)) {
        tf.current = {
          x: s.x,
          y: s.y,
          scale: Math.min(maxScale, Math.max(minScale, s.scale))
        };
        apply();
      }
    } catch {}
    // Flush on pagehide and unmount so a reload within the 200ms debounce
    // window doesn't drop the last pan/zoom.
    window.addEventListener('pagehide', flush);
    return () => {
      window.removeEventListener('pagehide', flush);
      flush();
    };
  }, []);
  React.useEffect(() => {
    const vp = vpRef.current;
    if (!vp) return;
    const zoomAt = (cx, cy, factor) => {
      const r = vp.getBoundingClientRect();
      const px = cx - r.left,
        py = cy - r.top;
      const t = tf.current;
      const next = Math.min(maxScale, Math.max(minScale, t.scale * factor));
      const k = next / t.scale;
      // --dc-inv-zoom consumers (.dc-sectionhead's CSS zoom, each section's
      // marginBottom) reflow on every scale change, vertically shifting the
      // world layout — so a world point mathematically pinned under the cursor
      // drifts as you zoom (content creeps up on zoom-in, down on zoom-out).
      // Anchor the DOM element under the cursor instead: record its screen Y,
      // apply the transform + --dc-inv-zoom, then cancel whatever vertical
      // drift the reflow introduced so it stays put on screen.
      let marker = null,
        markerY0 = 0;
      if (k !== 1) {
        const hit = document.elementFromPoint(cx, cy);
        marker = hit && hit.closest ? hit.closest('[data-dc-slot],[data-dc-section]') : null;
        if (marker) markerY0 = marker.getBoundingClientRect().top;
      }
      // keep the world point under the cursor fixed
      t.x = px - (px - t.x) * k;
      t.y = py - (py - t.y) * k;
      t.scale = next;
      apply();
      if (marker) {
        // A pure zoom around (cx, cy) maps screen Y → cy + (Y - cy) * k. Any
        // departure after the --dc-inv-zoom reflow is the layout drift.
        const drift = marker.getBoundingClientRect().top - (cy + (markerY0 - cy) * k);
        if (Math.abs(drift) > 0.1) {
          t.y -= drift;
          apply();
        }
      }
    };

    // Mouse-wheel vs trackpad-scroll heuristic. A physical wheel sends
    // line-mode deltas (Firefox) or large integer pixel deltas with no X
    // component (Chrome/Safari, typically multiples of 100/120). Trackpad
    // two-finger scroll sends small/fractional pixel deltas, often with
    // non-zero deltaX. ctrlKey is set by the browser for trackpad pinch.
    const isMouseWheel = e => e.deltaMode !== 0 || e.deltaX === 0 && Number.isInteger(e.deltaY) && Math.abs(e.deltaY) >= 40;
    const onWheel = e => {
      e.preventDefault();
      if (isGesturing) return; // Safari: gesture* owns the pinch — discard concurrent wheels
      if ((e.ctrlKey || e.metaKey) && !isMouseWheel(e)) {
        // trackpad pinch, or ctrl/cmd + smooth-scroll mouse. Notched
        // wheels fall through to the fixed-step branch below.
        zoomAt(e.clientX, e.clientY, Math.exp(-e.deltaY * 0.01));
      } else if (isMouseWheel(e)) {
        // notched mouse wheel — fixed-ratio step per click
        zoomAt(e.clientX, e.clientY, Math.exp(-Math.sign(e.deltaY) * 0.18));
      } else {
        // trackpad two-finger scroll — pan
        tf.current.x -= e.deltaX;
        tf.current.y -= e.deltaY;
        apply();
      }
    };

    // Safari sends native gesture* events for trackpad pinch with a smooth
    // e.scale; preferring these over the ctrl+wheel fallback gives a much
    // better feel there. No-ops on other browsers. Safari also fires
    // ctrlKey wheel events during the same pinch — isGesturing makes
    // onWheel drop those entirely so they neither zoom nor pan.
    let gsBase = 1;
    let isGesturing = false;
    const onGestureStart = e => {
      e.preventDefault();
      isGesturing = true;
      gsBase = tf.current.scale;
    };
    const onGestureChange = e => {
      e.preventDefault();
      zoomAt(e.clientX, e.clientY, gsBase * e.scale / tf.current.scale);
    };
    const onGestureEnd = e => {
      e.preventDefault();
      isGesturing = false;
    };

    // Drag-pan: middle button anywhere, or primary button on canvas
    // background (anything that isn't an artboard or an inline editor).
    let drag = null;
    const onPointerDown = e => {
      const onBg = !e.target.closest('[data-dc-slot], .dc-editable');
      if (!(e.button === 1 || e.button === 0 && onBg)) return;
      e.preventDefault();
      vp.setPointerCapture(e.pointerId);
      drag = {
        id: e.pointerId,
        lx: e.clientX,
        ly: e.clientY
      };
      vp.style.cursor = 'grabbing';
    };
    const onPointerMove = e => {
      if (!drag || e.pointerId !== drag.id) return;
      tf.current.x += e.clientX - drag.lx;
      tf.current.y += e.clientY - drag.ly;
      drag.lx = e.clientX;
      drag.ly = e.clientY;
      apply();
    };
    const onPointerUp = e => {
      if (!drag || e.pointerId !== drag.id) return;
      vp.releasePointerCapture(e.pointerId);
      drag = null;
      vp.style.cursor = '';
    };

    // Host-driven zoom (toolbar % menu). Zooms around viewport centre so the
    // visible midpoint stays fixed — matching the host's iframe-zoom feel.
    const onHostMsg = e => {
      const d = e.data;
      if (d && d.type === '__dc_set_zoom' && typeof d.scale === 'number') {
        const r = vp.getBoundingClientRect();
        zoomAt(r.left + r.width / 2, r.top + r.height / 2, d.scale / tf.current.scale);
      } else if (d && d.type === '__dc_probe') {
        // Host's [readyGen] reset asks whether a canvas is present; it
        // fires on the iframe's native 'load', which for canvases with
        // images/fonts is after our mount-time announce, so re-announce.
        // Clear the pan-tick guard so apply() re-posts the current scale
        // even if it's unchanged — the host just reset dcScale to 1.
        window.parent.postMessage({
          type: '__dc_present'
        }, '*');
        lastPostedScale.current = undefined;
        apply();
      }
    };
    window.addEventListener('message', onHostMsg);
    // Announce canvas mode so the host toolbar proxies its % control here
    // instead of scaling the iframe element (which would just shrink the
    // viewport window of an infinite canvas). The apply() that follows emits
    // the initial __dc_zoom so the toolbar % is correct before first pinch.
    // lastPostedScale reset mirrors the __dc_probe handler: the layout
    // effect's restore-path apply() may already have posted the restored
    // scale (before __dc_present), so clear the guard to re-post it in order.
    window.parent.postMessage({
      type: '__dc_present'
    }, '*');
    lastPostedScale.current = undefined;
    apply();
    vp.addEventListener('wheel', onWheel, {
      passive: false
    });
    vp.addEventListener('gesturestart', onGestureStart, {
      passive: false
    });
    vp.addEventListener('gesturechange', onGestureChange, {
      passive: false
    });
    vp.addEventListener('gestureend', onGestureEnd, {
      passive: false
    });
    vp.addEventListener('pointerdown', onPointerDown);
    vp.addEventListener('pointermove', onPointerMove);
    vp.addEventListener('pointerup', onPointerUp);
    vp.addEventListener('pointercancel', onPointerUp);
    return () => {
      window.removeEventListener('message', onHostMsg);
      vp.removeEventListener('wheel', onWheel);
      vp.removeEventListener('gesturestart', onGestureStart);
      vp.removeEventListener('gesturechange', onGestureChange);
      vp.removeEventListener('gestureend', onGestureEnd);
      vp.removeEventListener('pointerdown', onPointerDown);
      vp.removeEventListener('pointermove', onPointerMove);
      vp.removeEventListener('pointerup', onPointerUp);
      vp.removeEventListener('pointercancel', onPointerUp);
    };
  }, [apply, minScale, maxScale]);
  const gridSvg = `url("data:image/svg+xml,%3Csvg width='120' height='120' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M120 0H0v120' fill='none' stroke='${encodeURIComponent(DC.grid)}' stroke-width='1'/%3E%3C/svg%3E")`;
  return /*#__PURE__*/React.createElement("div", {
    ref: vpRef,
    className: "design-canvas",
    style: {
      height: '100vh',
      width: '100vw',
      background: DC.bg,
      overflow: 'hidden',
      overscrollBehavior: 'none',
      touchAction: 'none',
      position: 'relative',
      fontFamily: DC.font,
      boxSizing: 'border-box',
      ...style
    }
  }, /*#__PURE__*/React.createElement("div", {
    ref: worldRef,
    style: {
      position: 'absolute',
      top: 0,
      left: 0,
      transformOrigin: '0 0',
      willChange: 'transform',
      width: 'max-content',
      minWidth: '100%',
      minHeight: '100%',
      padding: '60px 0 80px'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      inset: -6000,
      backgroundImage: gridSvg,
      backgroundSize: '120px 120px',
      pointerEvents: 'none',
      zIndex: -1
    }
  }), children));
}

// ─────────────────────────────────────────────────────────────
// DCSection — editable title + h-row of artboards in persisted order
// ─────────────────────────────────────────────────────────────
function DCSection({
  id,
  title,
  subtitle,
  children,
  gap = 48
}) {
  const ctx = React.useContext(DCCtx);
  const sid = id ?? title;
  const all = React.Children.toArray(dcFlatten(children));
  const artboards = all.filter(c => c && c.type === DCArtboard);
  const rest = all.filter(c => !(c && c.type === DCArtboard));
  const sec = ctx && sid && ctx.section(sid) || {};
  // Must match DesignCanvas's srcKey computation exactly (it filters falsy
  // IDs), or onDelete persists a srcKey that DesignCanvas never recognizes.
  const allIds = artboards.map(a => a.props.id ?? a.props.label).filter(Boolean);
  const srcKey = allIds.join('\x1f');
  const hidden = sec.srcKey === srcKey ? sec.hidden || [] : [];
  const srcOrder = allIds.filter(k => !hidden.includes(k));
  const order = React.useMemo(() => {
    const kept = (sec.order || []).filter(k => srcOrder.includes(k));
    return [...kept, ...srcOrder.filter(k => !kept.includes(k))];
  }, [sec.order, srcOrder.join('|')]);
  const byId = Object.fromEntries(artboards.map(a => [a.props.id ?? a.props.label, a]));

  // marginBottom counter-scales so the on-screen gap between sections stays
  // constant — otherwise at low zoom the (world-space) gap collapses while
  // the screen-constant sectionhead below it doesn't, and the title reads as
  // belonging to the section above. paddingBottom below is just enough for
  // the 24px artboard-header (abs-positioned above each card) plus ~8px, so
  // the title sits tight against its own row at every zoom.
  return /*#__PURE__*/React.createElement("div", {
    "data-dc-section": sid,
    style: {
      marginBottom: 'calc(80px * var(--dc-inv-zoom, 1))',
      position: 'relative'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      padding: '0 60px'
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "dc-sectionhead",
    style: {
      paddingBottom: 36
    }
  }, /*#__PURE__*/React.createElement(DCEditable, {
    tag: "div",
    value: sec.title ?? title,
    onChange: v => ctx && sid && ctx.patchSection(sid, {
      title: v
    }),
    style: {
      fontSize: 28,
      fontWeight: 600,
      color: DC.title,
      letterSpacing: -0.4,
      marginBottom: 6,
      display: 'inline-block'
    }
  }), subtitle && /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 16,
      color: DC.subtitle
    }
  }, subtitle))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      gap,
      padding: '0 60px',
      alignItems: 'flex-start',
      width: 'max-content'
    }
  }, order.map(k => /*#__PURE__*/React.createElement(DCArtboardFrame, {
    key: k,
    sectionId: sid,
    artboard: byId[k],
    order: order,
    label: (sec.labels || {})[k] ?? byId[k].props.label,
    onRename: v => ctx && ctx.patchSection(sid, x => ({
      labels: {
        ...x.labels,
        [k]: v
      }
    })),
    onReorder: next => ctx && ctx.patchSection(sid, {
      order: next
    }),
    onDelete: () => ctx && ctx.patchSection(sid, x => ({
      hidden: [...(x.srcKey === srcKey ? x.hidden || [] : []), k],
      srcKey
    })),
    onFocus: () => ctx && ctx.setFocus(`${sid}/${k}`)
  }))), rest);
}

// DCArtboard — marker; rendered by DCArtboardFrame via DCSection.
function DCArtboard() {
  return null;
}

// Per-artboard export (kind: 'png' | 'html'). Both paths share the same
// self-contained clone: computed styles baked in, @font-face / <img> /
// inline-style background-image urls inlined as data URIs. PNG wraps the
// clone in foreignObject→canvas at 3× the artboard's natural width×height
// (same pipeline the host uses for page captures); HTML wraps it in a
// minimal standalone document. Both are independent of viewport zoom.
async function dcExport(node, w, h, name, kind) {
  try {
    await document.fonts.ready;
  } catch {}
  const toDataURL = url => fetch(url).then(r => r.blob()).then(b => new Promise(res => {
    const fr = new FileReader();
    fr.onload = () => res(fr.result);
    fr.onerror = () => res(url);
    fr.readAsDataURL(b);
  })).catch(() => url);

  // Collect @font-face rules. ss.cssRules throws SecurityError on
  // cross-origin sheets (e.g. fonts.googleapis.com) — in that case fetch
  // the CSS text directly (those endpoints send ACAO:*) and regex-extract
  // the blocks. @import and @media/@supports are walked so nested
  // @font-face rules aren't missed.
  const fontRules = [],
    pending = [],
    seen = new Set();
  const scrapeCss = href => {
    if (seen.has(href)) return;
    seen.add(href);
    pending.push(fetch(href).then(r => r.text()).then(css => {
      for (const m of css.match(/@font-face\s*{[^}]*}/g) || []) fontRules.push({
        css: m,
        base: href
      });
      for (const m of css.matchAll(/@import\s+(?:url\()?['"]?([^'")\s;]+)/g)) scrapeCss(new URL(m[1], href).href);
    }).catch(() => {}));
  };
  const walk = (rules, base) => {
    for (const r of rules) {
      if (r.type === CSSRule.FONT_FACE_RULE) fontRules.push({
        css: r.cssText,
        base
      });else if (r.type === CSSRule.IMPORT_RULE && r.styleSheet) {
        const ibase = r.styleSheet.href || base;
        try {
          walk(r.styleSheet.cssRules, ibase);
        } catch {
          scrapeCss(ibase);
        }
      } else if (r.cssRules) walk(r.cssRules, base);
    }
  };
  for (const ss of document.styleSheets) {
    const base = ss.href || location.href;
    try {
      walk(ss.cssRules, base);
    } catch {
      if (ss.href) scrapeCss(ss.href);
    }
  }
  while (pending.length) await pending.shift();
  const fontCss = (await Promise.all(fontRules.map(async rule => {
    let out = rule.css,
      m;
    const re = /url\((['"]?)([^'")]+)\1\)/g;
    while (m = re.exec(rule.css)) {
      if (m[2].indexOf('data:') === 0) continue;
      let abs;
      try {
        abs = new URL(m[2], rule.base).href;
      } catch {
        continue;
      }
      out = out.split(m[0]).join('url("' + (await toDataURL(abs)) + '")');
    }
    return out;
  }))).join('\n');
  const cloneStyled = src => {
    if (src.nodeType === 8 || src.nodeType === 1 && src.tagName === 'SCRIPT') return document.createTextNode('');
    const dst = src.cloneNode(false);
    if (src.nodeType === 1) {
      const cs = getComputedStyle(src);
      let txt = '';
      for (let i = 0; i < cs.length; i++) txt += cs[i] + ':' + cs.getPropertyValue(cs[i]) + ';';
      dst.setAttribute('style', txt + 'animation:none;transition:none;');
      if (src.tagName === 'CANVAS') try {
        const im = document.createElement('img');
        im.src = src.toDataURL();
        im.setAttribute('style', txt);
        return im;
      } catch {}
    }
    for (let c = src.firstChild; c; c = c.nextSibling) dst.appendChild(cloneStyled(c));
    return dst;
  };
  const clone = cloneStyled(node);
  clone.setAttribute('xmlns', 'http://www.w3.org/1999/xhtml');
  // Drop the card's own shadow/radius so the export is a flush w×h rect;
  // the artboard's own background (if any) is already in the computed style.
  clone.style.boxShadow = 'none';
  clone.style.borderRadius = '0';
  const jobs = [];
  clone.querySelectorAll('img').forEach(el => {
    const s = el.getAttribute('src');
    if (s && s.indexOf('data:') !== 0) jobs.push(toDataURL(el.src).then(d => el.setAttribute('src', d)));
  });
  [clone, ...clone.querySelectorAll('*')].forEach(el => {
    const bg = el.style.backgroundImage;
    if (!bg) return;
    let m;
    const re = /url\(["']?([^"')]+)["']?\)/g;
    while (m = re.exec(bg)) {
      const tok = m[0],
        url = m[1];
      if (url.indexOf('data:') === 0) continue;
      jobs.push(toDataURL(url).then(d => {
        el.style.backgroundImage = el.style.backgroundImage.split(tok).join('url("' + d + '")');
      }));
    }
  });
  await Promise.all(jobs);
  const xml = new XMLSerializer().serializeToString(clone);
  const save = (blob, ext) => {
    if (!blob) return;
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name + '.' + ext;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  };
  if (kind === 'html') {
    const html = '<!doctype html><html><head><meta charset="utf-8"><title>' + name + '</title>' + (fontCss ? '<style>' + fontCss + '</style>' : '') + '</head><body style="margin:0">' + xml + '</body></html>';
    return save(new Blob([html], {
      type: 'text/html'
    }), 'html');
  }

  // PNG: the SVG's own width/height must be the output resolution — an
  // <img>-loaded SVG rasterizes at its intrinsic size, so sizing it at 1×
  // and ctx.scale()-ing up would just upscale a 1× bitmap. viewBox maps the
  // w×h foreignObject onto the px·w × px·h SVG canvas so the browser renders
  // the HTML at full resolution.
  const px = 3;
  const svg = '<svg xmlns="http://www.w3.org/2000/svg" width="' + w * px + '" height="' + h * px + '" viewBox="0 0 ' + w + ' ' + h + '"><foreignObject width="' + w + '" height="' + h + '">' + (fontCss ? '<style><![CDATA[' + fontCss + ']]></style>' : '') + xml + '</foreignObject></svg>';
  const img = new Image();
  await new Promise((res, rej) => {
    img.onload = res;
    img.onerror = () => rej(new Error('svg load failed'));
    img.src = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(svg);
  });
  const cv = document.createElement('canvas');
  cv.width = w * px;
  cv.height = h * px;
  cv.getContext('2d').drawImage(img, 0, 0);
  cv.toBlob(blob => save(blob, 'png'), 'image/png');
}
function DCArtboardFrame({
  sectionId,
  artboard,
  label,
  order,
  onRename,
  onReorder,
  onFocus,
  onDelete
}) {
  const {
    id: rawId,
    label: rawLabel,
    width = 260,
    height = 480,
    children,
    style = {}
  } = artboard.props;
  const id = rawId ?? rawLabel;
  const ref = React.useRef(null);
  const cardRef = React.useRef(null);
  const menuRef = React.useRef(null);
  const [menuOpen, setMenuOpen] = React.useState(false);
  const [confirming, setConfirming] = React.useState(false);

  // ⋯ menu: close on any outside pointerdown. Two-click delete lives inside
  // the menu — first click arms the row, second commits; closing disarms.
  React.useEffect(() => {
    if (!menuOpen) {
      setConfirming(false);
      return;
    }
    const off = e => {
      if (!menuRef.current || !menuRef.current.contains(e.target)) setMenuOpen(false);
    };
    document.addEventListener('pointerdown', off, true);
    return () => document.removeEventListener('pointerdown', off, true);
  }, [menuOpen]);
  const doExport = kind => {
    setMenuOpen(false);
    if (!cardRef.current) return;
    const name = String(label || id || 'artboard').replace(/[^\w\s.-]+/g, '_');
    dcExport(cardRef.current, width, height, name, kind).catch(e => console.error('[design-canvas] export failed:', e));
  };

  // Live drag-reorder: dragged card sticks to cursor; siblings slide into
  // their would-be slots in real time via transforms. DOM order only
  // changes on drop.
  const onGripDown = e => {
    e.preventDefault();
    e.stopPropagation();
    const me = ref.current;
    // translateX is applied in local (pre-scale) space but pointer deltas and
    // getBoundingClientRect().left are screen-space — divide by the viewport's
    // current scale so the dragged card tracks the cursor at any zoom level.
    const scale = me.getBoundingClientRect().width / me.offsetWidth || 1;
    const peers = Array.from(document.querySelectorAll(`[data-dc-section="${sectionId}"] [data-dc-slot]`));
    const homes = peers.map(el => ({
      el,
      id: el.dataset.dcSlot,
      x: el.getBoundingClientRect().left
    }));
    const slotXs = homes.map(h => h.x);
    const startIdx = order.indexOf(id);
    const startX = e.clientX;
    let liveOrder = order.slice();
    me.classList.add('dc-dragging');
    const layout = () => {
      for (const h of homes) {
        if (h.id === id) continue;
        const slot = liveOrder.indexOf(h.id);
        h.el.style.transform = `translateX(${(slotXs[slot] - h.x) / scale}px)`;
      }
    };
    const move = ev => {
      const dx = ev.clientX - startX;
      me.style.transform = `translateX(${dx / scale}px)`;
      const cur = homes[startIdx].x + dx;
      let nearest = 0,
        best = Infinity;
      for (let i = 0; i < slotXs.length; i++) {
        const d = Math.abs(slotXs[i] - cur);
        if (d < best) {
          best = d;
          nearest = i;
        }
      }
      if (liveOrder.indexOf(id) !== nearest) {
        liveOrder = order.filter(k => k !== id);
        liveOrder.splice(nearest, 0, id);
        layout();
      }
    };
    const up = () => {
      document.removeEventListener('pointermove', move);
      document.removeEventListener('pointerup', up);
      const finalSlot = liveOrder.indexOf(id);
      me.classList.remove('dc-dragging');
      me.style.transform = `translateX(${(slotXs[finalSlot] - homes[startIdx].x) / scale}px)`;
      // After the settle transition, kill transitions + clear transforms +
      // commit the reorder in the same frame so there's no visual snap-back.
      setTimeout(() => {
        for (const h of homes) {
          h.el.style.transition = 'none';
          h.el.style.transform = '';
        }
        if (liveOrder.join('|') !== order.join('|')) onReorder(liveOrder);
        requestAnimationFrame(() => requestAnimationFrame(() => {
          for (const h of homes) h.el.style.transition = '';
        }));
      }, 180);
    };
    document.addEventListener('pointermove', move);
    document.addEventListener('pointerup', up);
  };
  return /*#__PURE__*/React.createElement("div", {
    ref: ref,
    "data-dc-slot": id,
    style: {
      position: 'relative',
      flexShrink: 0
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "dc-header",
    "data-omelette-chrome": "",
    style: {
      color: DC.label
    },
    onPointerDown: e => e.stopPropagation()
  }, /*#__PURE__*/React.createElement("div", {
    className: "dc-labelrow"
  }, /*#__PURE__*/React.createElement("div", {
    className: "dc-grip",
    onPointerDown: onGripDown,
    title: "Drag to reorder"
  }, /*#__PURE__*/React.createElement("svg", {
    width: "9",
    height: "13",
    viewBox: "0 0 9 13",
    fill: "currentColor"
  }, /*#__PURE__*/React.createElement("circle", {
    cx: "2",
    cy: "2",
    r: "1.1"
  }), /*#__PURE__*/React.createElement("circle", {
    cx: "7",
    cy: "2",
    r: "1.1"
  }), /*#__PURE__*/React.createElement("circle", {
    cx: "2",
    cy: "6.5",
    r: "1.1"
  }), /*#__PURE__*/React.createElement("circle", {
    cx: "7",
    cy: "6.5",
    r: "1.1"
  }), /*#__PURE__*/React.createElement("circle", {
    cx: "2",
    cy: "11",
    r: "1.1"
  }), /*#__PURE__*/React.createElement("circle", {
    cx: "7",
    cy: "11",
    r: "1.1"
  }))), /*#__PURE__*/React.createElement("div", {
    className: "dc-labeltext",
    onClick: onFocus,
    title: "Click to focus"
  }, /*#__PURE__*/React.createElement(DCEditable, {
    value: label,
    onChange: onRename,
    onClick: e => e.stopPropagation(),
    style: {
      fontSize: 15,
      fontWeight: 500,
      color: DC.label,
      lineHeight: 1
    }
  }))), /*#__PURE__*/React.createElement("div", {
    className: "dc-btns"
  }, /*#__PURE__*/React.createElement("div", {
    ref: menuRef,
    style: {
      position: 'relative'
    }
  }, /*#__PURE__*/React.createElement("button", {
    className: "dc-kebab",
    title: "More",
    onClick: () => setMenuOpen(o => !o)
  }, /*#__PURE__*/React.createElement("svg", {
    width: "12",
    height: "12",
    viewBox: "0 0 12 12",
    fill: "currentColor"
  }, /*#__PURE__*/React.createElement("circle", {
    cx: "2.5",
    cy: "6",
    r: "1.1"
  }), /*#__PURE__*/React.createElement("circle", {
    cx: "6",
    cy: "6",
    r: "1.1"
  }), /*#__PURE__*/React.createElement("circle", {
    cx: "9.5",
    cy: "6",
    r: "1.1"
  }))), menuOpen && /*#__PURE__*/React.createElement("div", {
    className: "dc-menu",
    onPointerDown: e => e.stopPropagation()
  }, /*#__PURE__*/React.createElement("button", {
    onClick: () => doExport('png')
  }, "Download PNG"), /*#__PURE__*/React.createElement("button", {
    onClick: () => doExport('html')
  }, "Download HTML"), /*#__PURE__*/React.createElement("hr", null), /*#__PURE__*/React.createElement("button", {
    className: "dc-danger",
    onClick: () => {
      if (confirming) {
        setMenuOpen(false);
        onDelete();
      } else setConfirming(true);
    }
  }, confirming ? 'Click again to delete' : 'Delete'))), /*#__PURE__*/React.createElement("button", {
    className: "dc-expand",
    onClick: onFocus,
    title: "Focus"
  }, /*#__PURE__*/React.createElement("svg", {
    width: "12",
    height: "12",
    viewBox: "0 0 12 12",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "1.6",
    strokeLinecap: "round"
  }, /*#__PURE__*/React.createElement("path", {
    d: "M7 1h4v4M5 11H1V7M11 1L7.5 4.5M1 11l3.5-3.5"
  }))))), /*#__PURE__*/React.createElement("div", {
    ref: cardRef,
    className: "dc-card",
    style: {
      borderRadius: 2,
      boxShadow: '0 1px 3px rgba(0,0,0,.08),0 4px 16px rgba(0,0,0,.06)',
      overflow: 'hidden',
      width,
      height,
      background: '#fff',
      ...style
    }
  }, children || /*#__PURE__*/React.createElement("div", {
    style: {
      height: '100%',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      color: '#bbb',
      fontSize: 13,
      fontFamily: DC.font
    }
  }, id)));
}

// Inline rename — commits on blur or Enter.
function DCEditable({
  value,
  onChange,
  style,
  tag = 'span',
  onClick
}) {
  const T = tag;
  return /*#__PURE__*/React.createElement(T, {
    className: "dc-editable",
    contentEditable: true,
    suppressContentEditableWarning: true,
    onClick: onClick,
    onPointerDown: e => e.stopPropagation(),
    onBlur: e => onChange && onChange(e.currentTarget.textContent),
    onKeyDown: e => {
      if (e.key === 'Enter') {
        e.preventDefault();
        e.currentTarget.blur();
      }
    },
    style: style
  }, value);
}

// ─────────────────────────────────────────────────────────────
// Focus mode — overlay one artboard; ←/→ within section, ↑/↓ across
// sections, Esc or backdrop click to exit.
// ─────────────────────────────────────────────────────────────
function DCFocusOverlay({
  entry,
  sectionMeta,
  sectionOrder
}) {
  const ctx = React.useContext(DCCtx);
  const {
    sectionId,
    artboard
  } = entry;
  const sec = ctx.section(sectionId);
  const meta = sectionMeta[sectionId];
  const peers = meta.slotIds;
  const aid = artboard.props.id ?? artboard.props.label;
  const idx = peers.indexOf(aid);
  const secIdx = sectionOrder.indexOf(sectionId);
  const go = d => {
    const n = peers[(idx + d + peers.length) % peers.length];
    if (n) ctx.setFocus(`${sectionId}/${n}`);
  };
  const goSection = d => {
    // Sections whose artboards are all deleted have slotIds:[] — step past
    // them to the next non-empty section so ↑/↓ doesn't dead-end.
    const n = sectionOrder.length;
    for (let i = 1; i < n; i++) {
      const ns = sectionOrder[((secIdx + d * i) % n + n) % n];
      const first = sectionMeta[ns] && sectionMeta[ns].slotIds[0];
      if (first) {
        ctx.setFocus(`${ns}/${first}`);
        return;
      }
    }
  };
  React.useEffect(() => {
    const k = e => {
      if (e.key === 'ArrowLeft') {
        e.preventDefault();
        go(-1);
      }
      if (e.key === 'ArrowRight') {
        e.preventDefault();
        go(1);
      }
      if (e.key === 'ArrowUp') {
        e.preventDefault();
        goSection(-1);
      }
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        goSection(1);
      }
    };
    document.addEventListener('keydown', k);
    return () => document.removeEventListener('keydown', k);
  });
  const {
    width = 260,
    height = 480,
    children
  } = artboard.props;
  const [vp, setVp] = React.useState({
    w: window.innerWidth,
    h: window.innerHeight
  });
  React.useEffect(() => {
    const r = () => setVp({
      w: window.innerWidth,
      h: window.innerHeight
    });
    window.addEventListener('resize', r);
    return () => window.removeEventListener('resize', r);
  }, []);
  const scale = Math.max(0.1, Math.min((vp.w - 200) / width, (vp.h - 260) / height, 2));
  const [ddOpen, setDd] = React.useState(false);
  const Arrow = ({
    dir,
    onClick
  }) => /*#__PURE__*/React.createElement("button", {
    onClick: e => {
      e.stopPropagation();
      onClick();
    },
    style: {
      position: 'absolute',
      top: '50%',
      [dir]: 28,
      transform: 'translateY(-50%)',
      border: 'none',
      background: 'rgba(255,255,255,.08)',
      color: 'rgba(255,255,255,.9)',
      width: 44,
      height: 44,
      borderRadius: 22,
      fontSize: 18,
      cursor: 'pointer',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      transition: 'background .15s'
    },
    onMouseEnter: e => e.currentTarget.style.background = 'rgba(255,255,255,.18)',
    onMouseLeave: e => e.currentTarget.style.background = 'rgba(255,255,255,.08)'
  }, /*#__PURE__*/React.createElement("svg", {
    width: "18",
    height: "18",
    viewBox: "0 0 18 18",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "2",
    strokeLinecap: "round"
  }, /*#__PURE__*/React.createElement("path", {
    d: dir === 'left' ? 'M11 3L5 9l6 6' : 'M7 3l6 6-6 6'
  })));

  // Portal to body so position:fixed is the real viewport regardless of any
  // transform on DesignCanvas's ancestors (including the canvas zoom itself).
  return ReactDOM.createPortal(/*#__PURE__*/React.createElement("div", {
    onClick: () => ctx.setFocus(null),
    onWheel: e => e.preventDefault(),
    style: {
      position: 'fixed',
      inset: 0,
      zIndex: 100,
      background: 'rgba(24,20,16,.6)',
      backdropFilter: 'blur(14px)',
      fontFamily: DC.font,
      color: '#fff'
    }
  }, /*#__PURE__*/React.createElement("div", {
    onClick: e => e.stopPropagation(),
    style: {
      position: 'absolute',
      top: 0,
      left: 0,
      right: 0,
      height: 72,
      display: 'flex',
      alignItems: 'flex-start',
      padding: '16px 20px 0',
      gap: 16
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'relative'
    }
  }, /*#__PURE__*/React.createElement("button", {
    onClick: () => setDd(o => !o),
    style: {
      border: 'none',
      background: 'transparent',
      color: '#fff',
      cursor: 'pointer',
      padding: '6px 8px',
      borderRadius: 6,
      textAlign: 'left',
      fontFamily: 'inherit'
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      display: 'flex',
      alignItems: 'center',
      gap: 8
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontSize: 18,
      fontWeight: 600,
      letterSpacing: -0.3
    }
  }, meta.title), /*#__PURE__*/React.createElement("svg", {
    width: "11",
    height: "11",
    viewBox: "0 0 11 11",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "1.8",
    strokeLinecap: "round",
    style: {
      opacity: .7
    }
  }, /*#__PURE__*/React.createElement("path", {
    d: "M2 4l3.5 3.5L9 4"
  }))), meta.subtitle && /*#__PURE__*/React.createElement("span", {
    style: {
      display: 'block',
      fontSize: 13,
      opacity: .6,
      fontWeight: 400,
      marginTop: 2
    }
  }, meta.subtitle)), ddOpen && /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      top: '100%',
      left: 0,
      marginTop: 4,
      background: '#2a251f',
      borderRadius: 8,
      boxShadow: '0 8px 32px rgba(0,0,0,.4)',
      padding: 4,
      minWidth: 200,
      zIndex: 10
    }
  }, sectionOrder.filter(sid => sectionMeta[sid].slotIds.length).map(sid => /*#__PURE__*/React.createElement("button", {
    key: sid,
    onClick: () => {
      setDd(false);
      const f = sectionMeta[sid].slotIds[0];
      if (f) ctx.setFocus(`${sid}/${f}`);
    },
    style: {
      display: 'block',
      width: '100%',
      textAlign: 'left',
      border: 'none',
      cursor: 'pointer',
      background: sid === sectionId ? 'rgba(255,255,255,.1)' : 'transparent',
      color: '#fff',
      padding: '8px 12px',
      borderRadius: 5,
      fontSize: 14,
      fontWeight: sid === sectionId ? 600 : 400,
      fontFamily: 'inherit'
    }
  }, sectionMeta[sid].title)))), /*#__PURE__*/React.createElement("div", {
    style: {
      flex: 1
    }
  }), /*#__PURE__*/React.createElement("button", {
    onClick: () => ctx.setFocus(null),
    onMouseEnter: e => e.currentTarget.style.background = 'rgba(255,255,255,.12)',
    onMouseLeave: e => e.currentTarget.style.background = 'transparent',
    style: {
      border: 'none',
      background: 'transparent',
      color: 'rgba(255,255,255,.7)',
      width: 32,
      height: 32,
      borderRadius: 16,
      fontSize: 20,
      cursor: 'pointer',
      lineHeight: 1,
      transition: 'background .12s'
    }
  }, "\xD7")), /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      top: 64,
      bottom: 56,
      left: 100,
      right: 100,
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      gap: 16
    }
  }, /*#__PURE__*/React.createElement("div", {
    onClick: e => e.stopPropagation(),
    style: {
      width: width * scale,
      height: height * scale,
      position: 'relative'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      width,
      height,
      transform: `scale(${scale})`,
      transformOrigin: 'top left',
      background: '#fff',
      borderRadius: 2,
      overflow: 'hidden',
      boxShadow: '0 20px 80px rgba(0,0,0,.4)'
    }
  }, children || /*#__PURE__*/React.createElement("div", {
    style: {
      height: '100%',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      color: '#bbb'
    }
  }, aid))), /*#__PURE__*/React.createElement("div", {
    onClick: e => e.stopPropagation(),
    style: {
      fontSize: 14,
      fontWeight: 500,
      opacity: .85,
      textAlign: 'center'
    }
  }, (sec.labels || {})[aid] ?? artboard.props.label, /*#__PURE__*/React.createElement("span", {
    style: {
      opacity: .5,
      marginLeft: 10,
      fontVariantNumeric: 'tabular-nums'
    }
  }, idx + 1, " / ", peers.length))), /*#__PURE__*/React.createElement(Arrow, {
    dir: "left",
    onClick: () => go(-1)
  }), /*#__PURE__*/React.createElement(Arrow, {
    dir: "right",
    onClick: () => go(1)
  }), /*#__PURE__*/React.createElement("div", {
    onClick: e => e.stopPropagation(),
    style: {
      position: 'absolute',
      bottom: 20,
      left: '50%',
      transform: 'translateX(-50%)',
      display: 'flex',
      gap: 8
    }
  }, peers.map((p, i) => /*#__PURE__*/React.createElement("button", {
    key: p,
    onClick: () => ctx.setFocus(`${sectionId}/${p}`),
    style: {
      border: 'none',
      padding: 0,
      cursor: 'pointer',
      width: 6,
      height: 6,
      borderRadius: 3,
      background: i === idx ? '#fff' : 'rgba(255,255,255,.3)'
    }
  })))), document.body);
}

// ─────────────────────────────────────────────────────────────
// Post-it — absolute-positioned sticky note
// ─────────────────────────────────────────────────────────────
function DCPostIt({
  children,
  top,
  left,
  right,
  bottom,
  rotate = -2,
  width = 180
}) {
  return /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      top,
      left,
      right,
      bottom,
      width,
      background: DC.postitBg,
      padding: '14px 16px',
      fontFamily: '"Comic Sans MS", "Marker Felt", "Segoe Print", cursive',
      fontSize: 14,
      lineHeight: 1.4,
      color: DC.postitText,
      boxShadow: '0 2px 8px rgba(0,0,0,0.12), 0 1px 2px rgba(0,0,0,0.08)',
      transform: `rotate(${rotate}deg)`,
      zIndex: 5
    }
  }, children);
}
Object.assign(window, {
  DesignCanvas,
  DCSection,
  DCArtboard,
  DCPostIt
});
})(); } catch (e) { __ds_ns.__errors.push({ path: "design-canvas.jsx", error: String((e && e.message) || e) }); }

// ui_kits/dashboard/app.jsx
try { (() => {
/* InstaCoach kit — app shell + routing. Loaded last. */
const AppIcon = window.Icon;
const NAV = [{
  id: "today",
  label: "Today",
  icon: "home"
}, {
  id: "plan",
  label: "Plan",
  icon: "target"
}, {
  id: "journal",
  label: "Journal",
  icon: "journal"
}, {
  id: "coach",
  label: "Coach",
  icon: "message"
}, {
  id: "progress",
  label: "Progress",
  icon: "chart"
}];
const TITLES = {
  today: {
    h: "Good morning, Maya",
    d: "Wednesday, June 6 · Week 3 of your plan"
  },
  plan: {
    h: "Your 4-week plan",
    d: "Grow into the director conversation"
  },
  coach: {
    h: "Coach Wren",
    d: "Usually replies in a moment"
  },
  journal: {
    h: "Journal",
    d: "Your reflections, in one calm place"
  },
  progress: {
    h: "Progress",
    d: "How your momentum is trending"
  }
};
function Sidebar({
  screen,
  go
}) {
  const {
    Logo
  } = window;
  return /*#__PURE__*/React.createElement("aside", {
    className: "sidebar"
  }, /*#__PURE__*/React.createElement(Logo, null), /*#__PURE__*/React.createElement("div", {
    className: "sidebar__section"
  }, "Coaching"), NAV.map(n => /*#__PURE__*/React.createElement("button", {
    key: n.id,
    className: `navitem${screen === n.id ? " navitem--active" : ""}`,
    onClick: () => go(n.id)
  }, /*#__PURE__*/React.createElement(AppIcon, {
    name: n.icon
  }), n.label, screen === n.id ? /*#__PURE__*/React.createElement("span", {
    className: "navdot"
  }) : null)), /*#__PURE__*/React.createElement("div", {
    className: "sidebar__spacer"
  }), /*#__PURE__*/React.createElement("button", {
    className: "navitem",
    onClick: () => go("settings")
  }, /*#__PURE__*/React.createElement(AppIcon, {
    name: "settings"
  }), " Settings"), /*#__PURE__*/React.createElement("div", {
    className: "sidebar__user"
  }, /*#__PURE__*/React.createElement("span", {
    className: "avatar"
  }, "MO"), /*#__PURE__*/React.createElement("div", {
    style: {
      flex: 1,
      minWidth: 0
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "name"
  }, "Maya Okafor"), /*#__PURE__*/React.createElement("div", {
    className: "sub"
  }, "Product Lead")), /*#__PURE__*/React.createElement(AppIcon, {
    name: "chevron-right",
    size: 16,
    style: {
      color: "var(--text-subtle)"
    }
  })));
}
function Placeholder({
  title
}) {
  return /*#__PURE__*/React.createElement("div", {
    className: "card",
    style: {
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      gap: 12,
      padding: 56,
      textAlign: "center"
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "lrow__icon",
    style: {
      width: 52,
      height: 52
    }
  }, /*#__PURE__*/React.createElement(AppIcon, {
    name: "bookmark",
    size: 24
  })), /*#__PURE__*/React.createElement("div", {
    className: "serif",
    style: {
      fontSize: 22
    }
  }, title, " is sketched in"), /*#__PURE__*/React.createElement("p", {
    className: "muted",
    style: {
      margin: 0,
      maxWidth: 380,
      lineHeight: 1.55
    }
  }, "This surface isn't part of the recreation yet. The shell, Today, Plan, and Coach screens show the full system in use."));
}
function App() {
  const [authed, setAuthed] = React.useState(false);
  const [screen, setScreen] = React.useState("today");
  const {
    SignIn,
    Today,
    Plan,
    Coach
  } = window;
  if (!authed) return /*#__PURE__*/React.createElement(SignIn, {
    onSignIn: () => setAuthed(true)
  });
  const t = TITLES[screen] || {
    h: screen,
    d: ""
  };
  const isChat = screen === "coach";
  return /*#__PURE__*/React.createElement("div", {
    className: "app"
  }, /*#__PURE__*/React.createElement(Sidebar, {
    screen: screen,
    go: setScreen
  }), /*#__PURE__*/React.createElement("main", {
    className: "main",
    style: isChat ? {
      display: "flex",
      flexDirection: "column",
      overflow: "hidden"
    } : null
  }, /*#__PURE__*/React.createElement("div", {
    className: "topbar"
  }, /*#__PURE__*/React.createElement("div", {
    className: "topbar__title"
  }, /*#__PURE__*/React.createElement("span", {
    className: "h"
  }, t.h), /*#__PURE__*/React.createElement("span", {
    className: "d"
  }, t.d)), /*#__PURE__*/React.createElement("div", {
    className: "topbar__actions"
  }, /*#__PURE__*/React.createElement("button", {
    className: "iconbtn",
    "aria-label": "Search"
  }, /*#__PURE__*/React.createElement(AppIcon, {
    name: "search"
  })), /*#__PURE__*/React.createElement("button", {
    className: "iconbtn",
    "aria-label": "Notifications"
  }, /*#__PURE__*/React.createElement(AppIcon, {
    name: "bell"
  })), /*#__PURE__*/React.createElement("button", {
    className: "btn btn--primary btn--sm",
    onClick: () => setScreen("coach")
  }, /*#__PURE__*/React.createElement(AppIcon, {
    name: "sparkles",
    size: 16
  }), " New session"))), isChat ? /*#__PURE__*/React.createElement(Coach, null) : /*#__PURE__*/React.createElement("div", {
    className: "content"
  }, screen === "today" && /*#__PURE__*/React.createElement(Today, {
    go: setScreen
  }), screen === "plan" && /*#__PURE__*/React.createElement(Plan, null), ["journal", "progress", "settings"].includes(screen) && /*#__PURE__*/React.createElement(Placeholder, {
    title: TITLES[screen] ? TITLES[screen].h : "This"
  }))));
}
ReactDOM.createRoot(document.getElementById("root")).render(/*#__PURE__*/React.createElement(App, null));
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/dashboard/app.jsx", error: String((e && e.message) || e) }); }

// ui_kits/dashboard/coach.jsx
try { (() => {
/* InstaCoach kit — Coach chat screen. Loaded after screens.jsx. */
const CoachIcon = window.Icon;
const COACH_REPLIES = ["That makes sense. What's the first sentence you'd want to say — out loud, in your words?", "Good. Notice you led with the impact, not the blame. How does saying it that way feel in your body?", "Let's keep that. Before the 1:1, take two slow breaths and reread that opening line. Want me to add it to today's plan?", "Done — it's on your plan for 4:00 PM. You've got a clear, kind way in. That's the whole job today."];
function Coach() {
  const [messages, setMessages] = React.useState([{
    from: "coach",
    text: "Hi Maya. Last week the 1:1 felt heavy. Want to spend a few minutes planning how you'll open it?"
  }, {
    from: "user",
    text: "Yeah. I keep softening it so much the point gets lost."
  }, {
    from: "coach",
    text: "That's a really common pattern. If you had one clear sentence to name what you need, what would it be?"
  }]);
  const [draft, setDraft] = React.useState("");
  const [typing, setTyping] = React.useState(false);
  const replyIdx = React.useRef(0);
  const scrollRef = React.useRef(null);
  React.useEffect(() => {
    const el = scrollRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [messages, typing]);
  const send = () => {
    const text = draft.trim();
    if (!text) return;
    setMessages(m => [...m, {
      from: "user",
      text
    }]);
    setDraft("");
    setTyping(true);
    setTimeout(() => {
      setTyping(false);
      const reply = COACH_REPLIES[replyIdx.current % COACH_REPLIES.length];
      replyIdx.current += 1;
      setMessages(m => [...m, {
        from: "coach",
        text: reply
      }]);
    }, 1300);
  };
  const onKey = e => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      send();
    }
  };
  return /*#__PURE__*/React.createElement("div", {
    className: "chat"
  }, /*#__PURE__*/React.createElement("div", {
    className: "chat__scroll",
    ref: scrollRef
  }, /*#__PURE__*/React.createElement("div", {
    className: "chat__thread"
  }, messages.map((m, i) => /*#__PURE__*/React.createElement("div", {
    className: `msg msg--${m.from}`,
    key: i
  }, m.from === "coach" ? /*#__PURE__*/React.createElement("span", {
    className: "avatar avatar--sm avatar--ring",
    style: {
      alignSelf: "flex-end"
    }
  }, "W") : null, /*#__PURE__*/React.createElement("div", {
    className: "msg__bubble"
  }, m.text))), typing ? /*#__PURE__*/React.createElement("div", {
    className: "msg msg--coach"
  }, /*#__PURE__*/React.createElement("span", {
    className: "avatar avatar--sm avatar--ring",
    style: {
      alignSelf: "flex-end"
    }
  }, "W"), /*#__PURE__*/React.createElement("div", {
    className: "msg__bubble"
  }, /*#__PURE__*/React.createElement("span", {
    className: "typing"
  }, /*#__PURE__*/React.createElement("span", null), /*#__PURE__*/React.createElement("span", null), /*#__PURE__*/React.createElement("span", null)))) : null)), /*#__PURE__*/React.createElement("div", {
    className: "chat__composer"
  }, /*#__PURE__*/React.createElement("div", {
    className: "chat__composer-inner"
  }, /*#__PURE__*/React.createElement("textarea", {
    className: "chat__input",
    placeholder: "Type your next thought\u2026  (Enter to send)",
    value: draft,
    onChange: e => setDraft(e.target.value),
    onKeyDown: onKey,
    rows: 1
  }), /*#__PURE__*/React.createElement("button", {
    className: "send",
    onClick: send,
    disabled: !draft.trim(),
    "aria-label": "Send"
  }, /*#__PURE__*/React.createElement(CoachIcon, {
    name: "arrow-up",
    size: 20
  })))));
}
window.Coach = Coach;
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/dashboard/coach.jsx", error: String((e && e.message) || e) }); }

// ui_kits/dashboard/icons.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
/* InstaCoach kit — inline icon set (Lucide geometry, 2px stroke).
 * Rendered as real React SVGs so they survive re-renders cleanly.
 */
const ICON_PATHS = {
  compass: /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("circle", {
    cx: "12",
    cy: "12",
    r: "10"
  }), /*#__PURE__*/React.createElement("polygon", {
    points: "16.24 7.76 14.12 14.12 7.76 16.24 9.88 9.88 16.24 7.76"
  })),
  target: /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("circle", {
    cx: "12",
    cy: "12",
    r: "10"
  }), /*#__PURE__*/React.createElement("circle", {
    cx: "12",
    cy: "12",
    r: "6"
  }), /*#__PURE__*/React.createElement("circle", {
    cx: "12",
    cy: "12",
    r: "2"
  })),
  "calendar-check": /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("path", {
    d: "M8 2v4"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M16 2v4"
  }), /*#__PURE__*/React.createElement("rect", {
    width: "18",
    height: "18",
    x: "3",
    y: "4",
    rx: "2"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M3 10h18"
  }), /*#__PURE__*/React.createElement("path", {
    d: "m9 16 2 2 4-4"
  })),
  message: /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("path", {
    d: "M7.9 20A9 9 0 1 0 4 16.1L2 22Z"
  })),
  sparkles: /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("path", {
    d: "M9.94 14.06A2 2 0 0 0 8.5 12.6l-5.6-1.45a.5.5 0 0 1 0-.96L8.5 8.74A2 2 0 0 0 9.94 7.3l1.45-5.6a.5.5 0 0 1 .96 0l1.45 5.6A2 2 0 0 0 15.7 8.74l5.6 1.45a.5.5 0 0 1 0 .96l-5.6 1.45a2 2 0 0 0-1.45 1.45l-1.45 5.6a.5.5 0 0 1-.96 0z"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M20 3v4"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M22 5h-4"
  })),
  clock: /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("circle", {
    cx: "12",
    cy: "12",
    r: "10"
  }), /*#__PURE__*/React.createElement("polyline", {
    points: "12 6 12 12 16 14"
  })),
  journal: /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("path", {
    d: "M12 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M18.4 2.6a1.4 1.4 0 0 1 3 3l-9 9a2 2 0 0 1-.85.5l-2.87.84a.5.5 0 0 1-.62-.62l.84-2.87a2 2 0 0 1 .5-.85z"
  })),
  "arrow-right": /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("path", {
    d: "M5 12h14"
  }), /*#__PURE__*/React.createElement("path", {
    d: "m12 5 7 7-7 7"
  })),
  "arrow-up": /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("path", {
    d: "M12 19V5"
  }), /*#__PURE__*/React.createElement("path", {
    d: "m5 12 7-7 7 7"
  })),
  bell: /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("path", {
    d: "M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M10.3 21a1.94 1.94 0 0 0 3.4 0"
  })),
  settings: /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("path", {
    d: "M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"
  }), /*#__PURE__*/React.createElement("circle", {
    cx: "12",
    cy: "12",
    r: "3"
  })),
  user: /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("path", {
    d: "M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"
  }), /*#__PURE__*/React.createElement("circle", {
    cx: "12",
    cy: "7",
    r: "4"
  })),
  check: /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("polyline", {
    points: "20 6 9 17 4 12"
  })),
  "chevron-right": /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("path", {
    d: "m9 18 6-6-6-6"
  })),
  flame: /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("path", {
    d: "M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.38-.5-2-1-3-1.07-2.14-.22-4.05 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.15.43-2.29 1-3a2.5 2.5 0 0 0 2.5 2.5z"
  })),
  home: /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("path", {
    d: "m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M9 22V12h6v10"
  })),
  "log-out": /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("path", {
    d: "M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"
  }), /*#__PURE__*/React.createElement("polyline", {
    points: "16 17 21 12 16 7"
  }), /*#__PURE__*/React.createElement("line", {
    x1: "21",
    x2: "9",
    y1: "12",
    y2: "12"
  })),
  search: /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("circle", {
    cx: "11",
    cy: "11",
    r: "8"
  }), /*#__PURE__*/React.createElement("path", {
    d: "m21 21-4.3-4.3"
  })),
  lock: /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("rect", {
    width: "18",
    height: "11",
    x: "3",
    y: "11",
    rx: "2"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M7 11V7a5 5 0 0 1 10 0v4"
  })),
  mail: /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("rect", {
    width: "20",
    height: "16",
    x: "2",
    y: "4",
    rx: "2"
  }), /*#__PURE__*/React.createElement("path", {
    d: "m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"
  })),
  send: /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("path", {
    d: "M14.54 2.46a1.4 1.4 0 0 1 1.81.93l3.9 14.32a1 1 0 0 1-1.79.83L14.5 13l-3.5 4-1-7-7-1 4-3.5L2.43 5.53a1 1 0 0 1 .83-1.79l11.28 3.07"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M22 2 11 13"
  })),
  chart: /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("path", {
    d: "M3 3v18h18"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M18 17V9"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M13 17V5"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M8 17v-3"
  })),
  bookmark: /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("path", {
    d: "m19 21-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z"
  })),
  plus: /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("path", {
    d: "M5 12h14"
  }), /*#__PURE__*/React.createElement("path", {
    d: "M12 5v14"
  }))
};
function Icon({
  name,
  size = 20,
  style,
  ...rest
}) {
  return /*#__PURE__*/React.createElement("svg", _extends({
    width: size,
    height: size,
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: "2",
    strokeLinecap: "round",
    strokeLinejoin: "round",
    style: {
      display: "block",
      flex: "none",
      ...style
    }
  }, rest), ICON_PATHS[name] || null);
}
window.Icon = Icon;
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/dashboard/icons.jsx", error: String((e && e.message) || e) }); }

// ui_kits/dashboard/screens.jsx
try { (() => {
/* InstaCoach kit — screens. Loaded after icons.jsx. */
const Icon = window.Icon;
const DATA = {
  user: {
    name: "Maya Okafor",
    role: "Product Lead · Northwind"
  },
  coach: {
    name: "Coach Wren",
    role: "Your coach"
  },
  focus: "Reframe one hard conversation.",
  planPct: 68,
  goals: [{
    title: "Lead with clarity under pressure",
    tag: "Communication",
    pct: 72
  }, {
    title: "Set boundaries without guilt",
    tag: "Wellbeing",
    pct: 55
  }, {
    title: "Grow into the director conversation",
    tag: "Career",
    pct: 40
  }],
  sessions: [{
    icon: "calendar-check",
    title: "Career growth check-in",
    when: "Today · 4:00 PM",
    tone: "brand"
  }, {
    icon: "clock",
    title: "Weekly reflection",
    when: "Thu · 8:30 AM",
    tone: "neutral"
  }, {
    icon: "target",
    title: "Boundaries practice",
    when: "Fri · 12:00 PM",
    tone: "neutral"
  }],
  reflections: [{
    title: "The 1:1 went better than I feared",
    date: "Yesterday",
    tag: "Confidence"
  }, {
    title: "Noticed I avoid conflict when tired",
    date: "Mon",
    tag: "Patterns"
  }, {
    title: "Said no to the extra project",
    date: "Last week",
    tag: "Boundaries"
  }]
};
function Logo() {
  return /*#__PURE__*/React.createElement("div", {
    className: "sidebar__logo"
  }, /*#__PURE__*/React.createElement("img", {
    src: "../../assets/logo/instacoach-mark.svg",
    alt: ""
  }), /*#__PURE__*/React.createElement("span", null, "InstaCoach"));
}

/* ------------------------------------------------------------------ Sign in */
function SignIn({
  onSignIn
}) {
  return /*#__PURE__*/React.createElement("div", {
    className: "signin"
  }, /*#__PURE__*/React.createElement("div", {
    className: "signin__brand"
  }, /*#__PURE__*/React.createElement("div", {
    className: "lock"
  }, /*#__PURE__*/React.createElement("img", {
    src: "../../assets/logo/instacoach-wordmark-cream.svg",
    alt: "InstaCoach",
    style: {
      height: 40,
      width: "auto"
    }
  })), /*#__PURE__*/React.createElement("div", {
    className: "signin__pitch"
  }, /*#__PURE__*/React.createElement("h1", null, "Coaching that meets you mid\u2011week."), /*#__PURE__*/React.createElement("p", null, "Your next move, every day \u2014 built around your goals, your calendar, and your pace.")), /*#__PURE__*/React.createElement("div", {
    className: "signin__foot"
  }, "Trusted by 40,000+ professionals growing on their own terms.")), /*#__PURE__*/React.createElement("div", {
    className: "signin__form-wrap"
  }, /*#__PURE__*/React.createElement("form", {
    className: "signin__form",
    onSubmit: e => {
      e.preventDefault();
      onSignIn();
    }
  }, /*#__PURE__*/React.createElement("h2", null, "Welcome back"), /*#__PURE__*/React.createElement("div", {
    className: "field"
  }, /*#__PURE__*/React.createElement("label", {
    htmlFor: "em"
  }, "Work email"), /*#__PURE__*/React.createElement("input", {
    className: "input",
    id: "em",
    type: "email",
    defaultValue: "maya@northwind.co",
    placeholder: "you@company.com"
  })), /*#__PURE__*/React.createElement("div", {
    className: "field"
  }, /*#__PURE__*/React.createElement("label", {
    htmlFor: "pw"
  }, "Password"), /*#__PURE__*/React.createElement("input", {
    className: "input",
    id: "pw",
    type: "password",
    defaultValue: "coaching",
    placeholder: "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022"
  })), /*#__PURE__*/React.createElement("button", {
    className: "btn btn--primary btn--lg btn--block",
    type: "submit"
  }, "Sign in"), /*#__PURE__*/React.createElement("div", {
    className: "divider"
  }, "or"), /*#__PURE__*/React.createElement("button", {
    className: "btn btn--secondary btn--block",
    type: "button",
    onClick: onSignIn
  }, "Continue with SSO"), /*#__PURE__*/React.createElement("p", {
    className: "muted",
    style: {
      fontSize: 13,
      textAlign: "center",
      margin: 0
    }
  }, "New here? ", /*#__PURE__*/React.createElement("a", {
    href: "#",
    style: {
      color: "var(--text-link)",
      fontWeight: 600,
      textDecoration: "none"
    },
    onClick: e => {
      e.preventDefault();
      onSignIn();
    }
  }, "Start your first session")))));
}

/* -------------------------------------------------------------------- Today */
function Today({
  go
}) {
  return /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("div", {
    className: "col-2"
  }, /*#__PURE__*/React.createElement("div", {
    className: "card",
    style: {
      display: "flex",
      flexDirection: "column",
      gap: 18
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      justifyContent: "space-between"
    }
  }, /*#__PURE__*/React.createElement("span", {
    className: "eyebrow"
  }, "Today's focus"), /*#__PURE__*/React.createElement("span", {
    className: "badge badge--success"
  }, /*#__PURE__*/React.createElement("span", {
    className: "dot"
  }), "On track")), /*#__PURE__*/React.createElement("div", {
    className: "serif",
    style: {
      fontSize: 30,
      lineHeight: 1.1
    }
  }, DATA.focus), /*#__PURE__*/React.createElement("p", {
    className: "muted",
    style: {
      margin: 0,
      fontSize: 15,
      lineHeight: 1.55,
      maxWidth: 460
    }
  }, "You named avoiding the 1:1 as a pattern. A 12\u2011minute session will help you plan how you'll open it."), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: 12,
      marginTop: 4
    }
  }, /*#__PURE__*/React.createElement("button", {
    className: "btn btn--primary",
    onClick: () => go("coach")
  }, /*#__PURE__*/React.createElement(Icon, {
    name: "sparkles",
    size: 18
  }), " Start session"), /*#__PURE__*/React.createElement("button", {
    className: "btn btn--ghost"
  }, "Swap focus"))), /*#__PURE__*/React.createElement("div", {
    className: "card card--inverse",
    style: {
      display: "flex",
      flexDirection: "column",
      gap: 18
    }
  }, /*#__PURE__*/React.createElement("span", {
    className: "eyebrow",
    style: {
      color: "var(--ocean-200)"
    }
  }, "4-week plan"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 18
    }
  }, /*#__PURE__*/React.createElement(Ring, {
    pct: DATA.planPct
  }), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      fontWeight: 600,
      fontSize: 16,
      marginBottom: 4
    }
  }, "Week 3 of 4"), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 13,
      color: "var(--ocean-200)"
    }
  }, "2 of 3 sessions done", /*#__PURE__*/React.createElement("br", null), "this week"))), /*#__PURE__*/React.createElement("button", {
    className: "btn btn--secondary btn--sm",
    style: {
      alignSelf: "flex-start"
    },
    onClick: () => go("plan")
  }, "View plan ", /*#__PURE__*/React.createElement(Icon, {
    name: "arrow-right",
    size: 16
  })))), /*#__PURE__*/React.createElement("div", {
    className: "stat-row",
    style: {
      marginTop: 20
    }
  }, /*#__PURE__*/React.createElement(StatCard, {
    icon: "clock",
    label: "Next check-in",
    value: "Today \xB7 4:00 PM",
    sub: "Career growth"
  }), /*#__PURE__*/React.createElement(StatCard, {
    icon: "flame",
    label: "Reflection streak",
    value: "5 weeks",
    sub: "Keep it going"
  }), /*#__PURE__*/React.createElement(StatCard, {
    icon: "chart",
    label: "Momentum",
    value: "+12%",
    sub: "vs. last month"
  })), /*#__PURE__*/React.createElement("div", {
    className: "card",
    style: {
      marginTop: 20,
      display: "flex",
      gap: 16,
      alignItems: "flex-start"
    }
  }, /*#__PURE__*/React.createElement("span", {
    className: "avatar avatar--lg avatar--ring"
  }, "W"), /*#__PURE__*/React.createElement("div", {
    style: {
      flex: 1
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 8,
      marginBottom: 6
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      fontWeight: 600,
      color: "var(--text-strong)"
    }
  }, DATA.coach.name), /*#__PURE__*/React.createElement("span", {
    className: "badge badge--brand"
  }, "Coach")), /*#__PURE__*/React.createElement("p", {
    style: {
      margin: "0 0 14px",
      fontSize: 15,
      lineHeight: 1.55,
      color: "var(--text-body)"
    }
  }, "\"Last week you said the 1:1 felt heavy. Want to spend 10 minutes planning how you'll open it \u2014 the first two sentences?\""), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: 10
    }
  }, /*#__PURE__*/React.createElement("button", {
    className: "btn btn--primary btn--sm",
    onClick: () => go("coach")
  }, "Reply to Wren"), /*#__PURE__*/React.createElement("button", {
    className: "btn btn--ghost btn--sm"
  }, "Later")))), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: 28,
      marginBottom: 12,
      display: "flex",
      alignItems: "baseline",
      justifyContent: "space-between"
    }
  }, /*#__PURE__*/React.createElement("h3", {
    className: "serif",
    style: {
      fontSize: 20,
      margin: 0
    }
  }, "Recent reflections"), /*#__PURE__*/React.createElement("button", {
    className: "btn btn--ghost btn--sm",
    onClick: () => go("journal")
  }, "Open journal ", /*#__PURE__*/React.createElement(Icon, {
    name: "arrow-right",
    size: 15
  }))), /*#__PURE__*/React.createElement("div", {
    className: "card",
    style: {
      padding: "8px 24px"
    }
  }, DATA.reflections.map((r, i) => /*#__PURE__*/React.createElement("div", {
    className: "lrow",
    key: i
  }, /*#__PURE__*/React.createElement("div", {
    className: "lrow__icon"
  }, /*#__PURE__*/React.createElement(Icon, {
    name: "journal"
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      flex: 1
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontWeight: 600,
      color: "var(--text-strong)",
      fontSize: 15
    }
  }, r.title), /*#__PURE__*/React.createElement("div", {
    className: "muted",
    style: {
      fontSize: 13
    }
  }, r.date)), /*#__PURE__*/React.createElement("span", {
    className: "tag",
    style: {
      cursor: "default"
    }
  }, r.tag), /*#__PURE__*/React.createElement(Icon, {
    name: "chevron-right",
    size: 18,
    style: {
      color: "var(--text-subtle)"
    }
  })))));
}
function StatCard({
  icon,
  label,
  value,
  sub
}) {
  return /*#__PURE__*/React.createElement("div", {
    className: "card",
    style: {
      display: "flex",
      flexDirection: "column",
      gap: 10
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "lrow__icon"
  }, /*#__PURE__*/React.createElement(Icon, {
    name: icon
  })), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "eyebrow",
    style: {
      marginBottom: 4
    }
  }, label), /*#__PURE__*/React.createElement("div", {
    className: "serif",
    style: {
      fontSize: 22
    }
  }, value), /*#__PURE__*/React.createElement("div", {
    className: "muted",
    style: {
      fontSize: 13,
      marginTop: 2
    }
  }, sub)));
}
function Ring({
  pct,
  size = 84,
  light
}) {
  const stroke = 9,
    r = (size - stroke) / 2,
    c = 2 * Math.PI * r;
  return /*#__PURE__*/React.createElement("div", {
    style: {
      position: "relative",
      width: size,
      height: size,
      display: "grid",
      placeItems: "center",
      flex: "none"
    }
  }, /*#__PURE__*/React.createElement("svg", {
    width: size,
    height: size,
    style: {
      transform: "rotate(-90deg)"
    }
  }, /*#__PURE__*/React.createElement("circle", {
    cx: size / 2,
    cy: size / 2,
    r: r,
    fill: "none",
    stroke: light ? "var(--surface-sunken)" : "rgba(255,255,255,0.16)",
    strokeWidth: stroke
  }), /*#__PURE__*/React.createElement("circle", {
    cx: size / 2,
    cy: size / 2,
    r: r,
    fill: "none",
    stroke: light ? "var(--primary)" : "var(--accent)",
    strokeWidth: stroke,
    strokeLinecap: "round",
    strokeDasharray: c,
    strokeDashoffset: c - pct / 100 * c
  })), /*#__PURE__*/React.createElement("span", {
    style: {
      position: "absolute",
      fontWeight: 700,
      fontSize: size * 0.26,
      color: light ? "var(--text-strong)" : "var(--text-inverse)"
    }
  }, pct, "%"));
}

/* --------------------------------------------------------------------- Plan */
function Plan() {
  const [week, setWeek] = React.useState("w3");
  const weeks = [{
    value: "w1",
    label: "Week 1"
  }, {
    value: "w2",
    label: "Week 2"
  }, {
    value: "w3",
    label: "Week 3"
  }, {
    value: "w4",
    label: "Week 4"
  }];
  return /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("div", {
    className: "card card--inverse",
    style: {
      display: "flex",
      alignItems: "center",
      gap: 24,
      marginBottom: 22
    }
  }, /*#__PURE__*/React.createElement(Ring, {
    pct: DATA.planPct,
    size: 92
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      flex: 1
    }
  }, /*#__PURE__*/React.createElement("span", {
    className: "eyebrow",
    style: {
      color: "var(--ocean-200)"
    }
  }, "Plan \xB7 Grow into the director conversation"), /*#__PURE__*/React.createElement("div", {
    className: "serif",
    style: {
      fontSize: 24,
      color: "var(--text-inverse)",
      margin: "6px 0 4px"
    }
  }, "You're 68% through a strong month."), /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 14,
      color: "var(--ocean-200)"
    }
  }, "3 goals \xB7 9 of 12 sessions complete")), /*#__PURE__*/React.createElement("button", {
    className: "btn btn--accent"
  }, "Add a goal ", /*#__PURE__*/React.createElement(Icon, {
    name: "plus",
    size: 16
  }))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: 18,
      marginBottom: 18,
      borderBottom: "1px solid var(--border-subtle)"
    }
  }, weeks.map(w => /*#__PURE__*/React.createElement("button", {
    key: w.value,
    onClick: () => setWeek(w.value),
    style: {
      background: "none",
      border: "none",
      cursor: "pointer",
      padding: "11px 2px",
      marginBottom: -1,
      fontWeight: 600,
      fontSize: 14,
      color: week === w.value ? "var(--primary)" : "var(--text-muted)",
      borderBottom: week === w.value ? "2px solid var(--primary)" : "2px solid transparent"
    }
  }, w.label))), /*#__PURE__*/React.createElement("div", {
    className: "stack",
    style: {
      gap: 16
    }
  }, DATA.goals.map((g, i) => /*#__PURE__*/React.createElement("div", {
    className: "card",
    key: i,
    style: {
      display: "flex",
      flexDirection: "column",
      gap: 14
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 12
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "lrow__icon"
  }, /*#__PURE__*/React.createElement(Icon, {
    name: "target"
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      flex: 1
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontWeight: 600,
      color: "var(--text-strong)",
      fontSize: 16
    }
  }, g.title), /*#__PURE__*/React.createElement("span", {
    className: "tag tag--selected",
    style: {
      cursor: "default",
      marginTop: 6
    }
  }, g.tag)), /*#__PURE__*/React.createElement("span", {
    className: "badge badge--neutral"
  }, g.pct, "%")), /*#__PURE__*/React.createElement("div", {
    className: "prog-track"
  }, /*#__PURE__*/React.createElement("div", {
    className: "prog-fill",
    style: {
      width: g.pct + "%"
    }
  }))))), /*#__PURE__*/React.createElement("h3", {
    className: "serif",
    style: {
      fontSize: 20,
      margin: "28px 0 12px"
    }
  }, "This week's sessions"), /*#__PURE__*/React.createElement("div", {
    className: "card",
    style: {
      padding: "8px 24px"
    }
  }, DATA.sessions.map((s, i) => /*#__PURE__*/React.createElement("div", {
    className: "lrow",
    key: i
  }, /*#__PURE__*/React.createElement("div", {
    className: "lrow__icon"
  }, /*#__PURE__*/React.createElement(Icon, {
    name: s.icon
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      flex: 1
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontWeight: 600,
      color: "var(--text-strong)",
      fontSize: 15
    }
  }, s.title), /*#__PURE__*/React.createElement("div", {
    className: "muted",
    style: {
      fontSize: 13
    }
  }, s.when)), /*#__PURE__*/React.createElement("button", {
    className: "btn btn--secondary btn--sm"
  }, "Start")))));
}
window.Logo = Logo;
window.SignIn = SignIn;
window.Today = Today;
window.Plan = Plan;
window.Ring = Ring;
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/dashboard/screens.jsx", error: String((e && e.message) || e) }); }

__ds_ns.Avatar = __ds_scope.Avatar;

__ds_ns.Badge = __ds_scope.Badge;

__ds_ns.Card = __ds_scope.Card;

__ds_ns.Progress = __ds_scope.Progress;

__ds_ns.Tag = __ds_scope.Tag;

__ds_ns.Dialog = __ds_scope.Dialog;

__ds_ns.Toast = __ds_scope.Toast;

__ds_ns.Button = __ds_scope.Button;

__ds_ns.Checkbox = __ds_scope.Checkbox;

__ds_ns.IconButton = __ds_scope.IconButton;

__ds_ns.Input = __ds_scope.Input;

__ds_ns.Select = __ds_scope.Select;

__ds_ns.Switch = __ds_scope.Switch;

__ds_ns.Textarea = __ds_scope.Textarea;

__ds_ns.Tabs = __ds_scope.Tabs;

})();
