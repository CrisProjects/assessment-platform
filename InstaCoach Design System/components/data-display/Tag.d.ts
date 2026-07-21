import * as React from "react";

/** Filter / keyword chip, optionally selectable or removable. */
export interface TagProps extends React.HTMLAttributes<HTMLSpanElement> {
  /** Filled "selected" state. @default false */
  selected?: boolean;
  /** Show a dismiss "×" and call this when clicked. */
  onRemove?: (e: React.MouseEvent) => void;
  /** Leading icon node. */
  icon?: React.ReactNode;
  children?: React.ReactNode;
}

export function Tag(props: TagProps): JSX.Element;
