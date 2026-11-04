import { isScalar, visit, type Document } from "yaml";
import { SourceAttention } from "./source-http.js";

/** Validate before toJS: distinct YAML keys can otherwise collapse to one object property. */
export function validatePnpmMappingKeys(document: Document): void {
  visit(document, { Pair: (_key, pair) => {
    if (!isScalar(pair.key) || typeof pair.key.value !== "string") throw new SourceAttention("unsupported_pnpm_yaml_key");
    if (pair.key.value === "<<") throw new SourceAttention("unsupported_yaml_merge");
  } });
}
