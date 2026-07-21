import * as React from "react";

/** Labelled text input with optional icon, hint, and error state. */
export interface InputProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, "children"> {
  /** Field label rendered above the input. */
  label?: string;
  /** Helper text below the field. */
  hint?: string;
  /** Error message — also switches the field to its error style. */
  error?: string;
  /** Leading icon node (a Lucide <i> or svg). */
  icon?: React.ReactNode;
}

export function Input(props: InputProps): JSX.Element;
