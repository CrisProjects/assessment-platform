import * as React from "react";

/** Multi-line text field for reflections and notes. */
export interface TextareaProps extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {
  label?: string;
  hint?: string;
  error?: string;
}

export function Textarea(props: TextareaProps): JSX.Element;
