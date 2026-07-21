import * as React from "react";

/** Progress indicator — linear bar or radial ring. */
export interface ProgressProps extends React.HTMLAttributes<HTMLDivElement> {
  /** Completion 0–100. */
  value?: number;
  /** @default "bar" */
  variant?: "bar" | "ring";
  /** @default "brand" */
  tone?: "brand" | "accent" | "success";
  /** Label shown above a bar. */
  label?: string;
  /** Show the % value. @default true */
  showValue?: boolean;
  /** Ring diameter in px. @default 64 */
  size?: number;
}

export function Progress(props: ProgressProps): JSX.Element;
