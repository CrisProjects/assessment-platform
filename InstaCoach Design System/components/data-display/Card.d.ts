import * as React from "react";

/**
 * Surface container — the core layout primitive.
 *
 * @startingPoint section="Layout" subtitle="Soft card surface with optional hover lift" viewport="700x300"
 */
export interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  /** Inner padding. @default "md" */
  padding?: "sm" | "md" | "lg";
  /** Adds hover lift + pointer cursor for clickable cards. @default false */
  interactive?: boolean;
  /** Dark forest surface with inverse text. @default false */
  inverse?: boolean;
  /** Remove the shadow (border only). @default false */
  flat?: boolean;
  children?: React.ReactNode;
}

export function Card(props: CardProps): JSX.Element;
