import { isScalar, visit, type Document } from "yaml";
import { SourceAttention } from "./source-http.js";

/** Supported root/descendant locators only; this does not establish workspace membership. */
export function validatePnpmImporterPath(importer: unknown): void {
  if (typeof importer !== "string" || !importer.length || importer.length > 1024
    || /[\\\u0000-\u001f\u007f]/u.test(importer)
    || (importer !== "." && importer.split("/").some(part => !part || part === "." || part === ".."))) {
    throw new SourceAttention("invalid_pnpm_importer_path");
  }
}

/** Validate before toJS: distinct YAML keys can otherwise collapse to one object property. */
export function validatePnpmMappingKeys(document: Document): void {
  visit(document, { Pair: (_key, pair) => {
    if (!isScalar(pair.key) || typeof pair.key.value !== "string") throw new SourceAttention("unsupported_pnpm_yaml_key");
    if (pair.key.value === "<<") throw new SourceAttention("unsupported_yaml_merge");
  } });
}
