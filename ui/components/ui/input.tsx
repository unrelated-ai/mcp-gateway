"use client";

import {
  forwardRef,
  useId,
  type InputHTMLAttributes,
  type ReactNode,
  type SelectHTMLAttributes,
  type TextareaHTMLAttributes,
} from "react";

export const fieldControlStyles = `
  w-full rounded-md border border-edge-strong bg-well
  text-fg placeholder:text-faint
  transition-colors duration-150
  focus:outline-none focus:ring-2 focus:ring-accent/60 focus:border-accent/60
  hover:border-faint/40
  disabled:opacity-50 disabled:cursor-not-allowed
`;

const errorControlStyles = "border-danger/50 focus:ring-danger/50 focus:border-danger/50";

interface FieldProps {
  label?: string;
  hint?: string;
  error?: string;
  /** id of the control this field wraps */
  htmlFor: string;
  hintId: string;
  children: ReactNode;
}

function Field({ label, hint, error, htmlFor, hintId, children }: FieldProps) {
  return (
    <div className="space-y-1.5">
      {label && (
        <label htmlFor={htmlFor} className="block text-sm font-medium text-fg">
          {label}
        </label>
      )}
      {children}
      {hint && !error && (
        <p id={hintId} className="text-xs text-faint">
          {hint}
        </p>
      )}
      {error && (
        <p id={hintId} className="text-xs text-danger">
          {error}
        </p>
      )}
    </div>
  );
}

interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  hint?: string;
  error?: string;
}

export const Input = forwardRef<HTMLInputElement, InputProps>(
  ({ className = "", label, hint, error, id, ...props }, ref) => {
    const autoId = useId();
    const inputId = id ?? autoId;
    const hintId = `${inputId}-hint`;

    return (
      <Field label={label} hint={hint} error={error} htmlFor={inputId} hintId={hintId}>
        <input
          ref={ref}
          id={inputId}
          aria-invalid={error ? true : undefined}
          aria-describedby={hint || error ? hintId : undefined}
          className={`${fieldControlStyles} h-9 px-3 text-sm ${error ? errorControlStyles : ""} ${className}`}
          {...props}
        />
      </Field>
    );
  },
);

Input.displayName = "Input";

interface TextareaProps extends TextareaHTMLAttributes<HTMLTextAreaElement> {
  label?: string;
  hint?: string;
  error?: string;
}

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaProps>(
  ({ className = "", label, hint, error, id, ...props }, ref) => {
    const autoId = useId();
    const inputId = id ?? autoId;
    const hintId = `${inputId}-hint`;

    return (
      <Field label={label} hint={hint} error={error} htmlFor={inputId} hintId={hintId}>
        <textarea
          ref={ref}
          id={inputId}
          aria-invalid={error ? true : undefined}
          aria-describedby={hint || error ? hintId : undefined}
          className={`${fieldControlStyles} px-3 py-2 text-sm font-mono resize-none ${error ? errorControlStyles : ""} ${className}`}
          {...props}
        />
      </Field>
    );
  },
);

Textarea.displayName = "Textarea";

interface SelectProps extends SelectHTMLAttributes<HTMLSelectElement> {
  label?: string;
  hint?: string;
  error?: string;
}

export const Select = forwardRef<HTMLSelectElement, SelectProps>(
  ({ className = "", label, hint, error, id, children, ...props }, ref) => {
    const autoId = useId();
    const inputId = id ?? autoId;
    const hintId = `${inputId}-hint`;

    return (
      <Field label={label} hint={hint} error={error} htmlFor={inputId} hintId={hintId}>
        <div className="relative">
          <select
            ref={ref}
            id={inputId}
            aria-invalid={error ? true : undefined}
            aria-describedby={hint || error ? hintId : undefined}
            className={`${fieldControlStyles} h-9 appearance-none pl-3 pr-8 text-sm ${error ? errorControlStyles : ""} ${className}`}
            {...props}
          >
            {children}
          </select>
          <svg
            aria-hidden="true"
            className="pointer-events-none absolute right-2.5 top-1/2 size-4 -translate-y-1/2 text-faint"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth={2}
          >
            <path strokeLinecap="round" strokeLinejoin="round" d="M6 9l6 6 6-6" />
          </svg>
        </div>
      </Field>
    );
  },
);

Select.displayName = "Select";
