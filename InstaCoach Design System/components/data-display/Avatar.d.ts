import * as React from "react";

/** User avatar with image or initials fallback. */
export interface AvatarProps extends React.HTMLAttributes<HTMLSpanElement> {
  /** Image URL. Falls back to initials when absent. */
  src?: string;
  /** Full name — used for initials and alt text. */
  name?: string;
  /** @default "md" */
  size?: "sm" | "md" | "lg" | "xl";
  /** Forest focus ring (e.g. active coach). @default false */
  ring?: boolean;
  /** Green presence dot. @default false */
  status?: boolean;
}

export function Avatar(props: AvatarProps): JSX.Element;
