"use client";

import { Input, Select } from "@/components/ui";
import type { AuthConfig } from "@/src/lib/tenantApi";

const secretHint = "Enter a value or a tenant secret reference, e.g. ${secret:API_TOKEN}.";

function emptyAuth(type: AuthConfig["type"]): AuthConfig {
  switch (type) {
    case "bearer":
      return { type, token: "" };
    case "basic":
      return { type, username: "", password: "" };
    case "header":
    case "query":
      return { type, name: "", value: "" };
    default:
      return { type: "none" };
  }
}

export function OpenApiAuthFields({
  auth,
  onChange,
  disabled,
}: {
  auth: AuthConfig;
  onChange: (auth: AuthConfig) => void;
  disabled: boolean;
}) {
  return (
    <fieldset disabled={disabled} className="mt-6 space-y-4">
      <Select
        label="Source authentication"
        value={auth.type}
        onChange={(event) => onChange(emptyAuth(event.target.value as AuthConfig["type"]))}
        hint="Used to download the spec and make API calls."
      >
        <option value="none">None</option>
        <option value="bearer">Bearer token</option>
        <option value="basic">Basic auth</option>
        <option value="header">Custom header</option>
        <option value="query">Query parameter</option>
      </Select>
      {auth.type === "bearer" && (
        <Input
          label="Bearer token"
          type="password"
          autoComplete="off"
          value={auth.token}
          onChange={(event) => onChange({ ...auth, token: event.target.value })}
          hint={secretHint}
          className="font-mono"
        />
      )}
      {auth.type === "basic" && (
        <div className="grid gap-4 sm:grid-cols-2">
          <Input
            label="Username"
            value={auth.username}
            onChange={(event) => onChange({ ...auth, username: event.target.value })}
            autoComplete="off"
          />
          <Input
            label="Password"
            type="password"
            autoComplete="off"
            value={auth.password}
            onChange={(event) => onChange({ ...auth, password: event.target.value })}
            hint={secretHint}
          />
        </div>
      )}
      {(auth.type === "header" || auth.type === "query") && (
        <div className="grid gap-4 sm:grid-cols-2">
          <Input
            label={auth.type === "header" ? "Header name" : "Query parameter name"}
            value={auth.name}
            onChange={(event) => onChange({ ...auth, name: event.target.value })}
            className="font-mono"
          />
          <Input
            label={auth.type === "header" ? "Header value" : "Query parameter value"}
            type="password"
            autoComplete="off"
            value={auth.value}
            onChange={(event) => onChange({ ...auth, value: event.target.value })}
            hint={secretHint}
            className="font-mono"
          />
        </div>
      )}
    </fieldset>
  );
}
