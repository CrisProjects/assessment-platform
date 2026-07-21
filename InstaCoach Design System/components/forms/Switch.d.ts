import * as React from "react";

/** Toggle switch for instant on/off settings. */
export interface SwitchProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, "type"> {
  label?: string;
}

export function Switch(props: SwitchProps): JSX.Element;
