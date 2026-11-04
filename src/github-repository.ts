import { SourceAttention } from "./source-http.js";

export function repository(value: string): string {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9-]{0,38}\/[a-zA-Z0-9_.-]{1,100}$/u.test(value)
    || value.endsWith("/.") || value.endsWith("/..")) throw new SourceAttention("invalid_repository");
  return value.toLowerCase();
}
