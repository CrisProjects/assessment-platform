import * as React from "react";

/** Square icon-only button — toolbar actions, close buttons, nav controls. */
export interface IconButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  /** @default "plain" */
  variant?: "plain" | "solid" | "outline";
  /** @default "md" */
  size?: "sm" | "md" | "lg";
  /** Required for accessibility. */
  "aria-label": string;
  /** Icon node (a Lucide <i> or svg). */
  children?: React.ReactNode;
}

export function IconButton(props: IconButtonProps): JSX.Element;
