import * as React from "react";

/**
 * InstaCoach primary action button.
 *
 * @startingPoint section="Forms" subtitle="Primary / secondary / ghost / accent / danger" viewport="700x160"
 */
export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  /** Visual style. @default "primary" */
  variant?: "primary" | "secondary" | "ghost" | "accent" | "danger";
  /** Size. @default "md" */
  size?: "sm" | "md" | "lg";
  /** Icon node rendered before the label (e.g. a Lucide <i>). */
  leadingIcon?: React.ReactNode;
  /** Icon node rendered after the label. */
  trailingIcon?: React.ReactNode;
  /** Stretch to fill the container width. @default false */
  fullWidth?: boolean;
  /** Render as a different element, e.g. "a" for links. @default "button" */
  as?: "button" | "a";
  children?: React.ReactNode;
}

export function Button(props: ButtonProps): JSX.Element;
