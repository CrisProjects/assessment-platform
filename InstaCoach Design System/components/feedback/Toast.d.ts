import * as React from "react";

/** Toast notification on the dark surface. Presentational. */
export interface ToastProps extends React.HTMLAttributes<HTMLDivElement> {
  /** @default "success" */
  tone?: "success" | "danger" | "info";
  title?: string;
  /** Optional dismiss handler — shows a close button. */
  onClose?: () => void;
  children?: React.ReactNode;
}

export function Toast(props: ToastProps): JSX.Element;
