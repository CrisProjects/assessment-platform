import * as React from "react";

/** Styled native select with a custom chevron. */
export interface SelectProps extends React.SelectHTMLAttributes<HTMLSelectElement> {
  label?: string;
  /** Convenience: render options from data instead of children. */
  options?: Array<{ value: string; label: string }>;
  children?: React.ReactNode;
}

export function Select(props: SelectProps): JSX.Element;
