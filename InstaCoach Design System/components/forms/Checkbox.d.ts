import * as React from "react";

/** Checkbox with optional label and description. */
export interface CheckboxProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, "type"> {
  label?: string;
  description?: string;
}

export function Checkbox(props: CheckboxProps): JSX.Element;
