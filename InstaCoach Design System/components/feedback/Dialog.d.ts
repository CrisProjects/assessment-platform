import * as React from "react";

/** Modal dialog with scrim. Renders nothing when `open` is false. */
export interface DialogProps {
  open: boolean;
  onClose?: () => void;
  /** Serif title. */
  title?: string;
  /** Supporting text below the title. */
  description?: string;
  /** Footer node — typically action Buttons. */
  footer?: React.ReactNode;
  /** Custom body content between description and footer. */
  children?: React.ReactNode;
}

export function Dialog(props: DialogProps): JSX.Element | null;
