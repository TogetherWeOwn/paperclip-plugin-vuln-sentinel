import { describe, expect, it } from "vitest";
import { osvVersionStatus } from "./ranges.js";
import type { OsvRange } from "./ranges.js";

function status(version: string, ranges: OsvRange[], versions: string[] = []) {
  return osvVersionStatus([{ package: { ecosystem: "npm", name: "pkg" }, ranges, versions }], "npm", "pkg", version);
}
const range = (events: OsvRange["events"]): OsvRange => ({ type: "SEMVER", events });

describe("OSV range proof", () => {
  it.each([
    ["0.0.0", "affected"], ["1.2.2", "affected"], ["1.2.3", "outside"], ["2.0.0", "outside"],
  ] as const)("introduced=0 and fixed boundary: %s -> %s", (version, expected) => {
    expect(status(version, [range([{ introduced: "0" }, { fixed: "1.2.3" }])])).toBe(expected);
  });

  it("supports disjoint intervals, inclusive last_affected, exclusive limit and open ranges", () => {
    const ranges = [range([{ introduced: "1.0.0" }, { last_affected: "1.1.0" }, { introduced: "2.0.0" }, { limit: "3.0.0" }])];
    expect(status("1.1.0", ranges)).toBe("affected");
    expect(status("1.1.1", ranges)).toBe("outside");
    expect(status("2.0.0", ranges)).toBe("affected");
    expect(status("3.0.0", ranges)).toBe("outside");
    expect(status("9.0.0", [range([{ introduced: "2.0.0" }])])).toBe("affected");
  });

  it.each<{ events: OsvRange["events"] }>([
    { events: [] }, { events: [{ fixed: "1.0.0" }] },
    { events: [{ introduced: "1.0.0" }, { introduced: "2.0.0" }] },
    { events: [{ introduced: "2.0.0" }, { fixed: "1.0.0" }] }, { events: [{ introduced: "invalid" }] },
    { events: [{ introduced: "1.0.0", fixed: "2.0.0" }] }, { events: [{ introduced: "0" }, { unexpected: "1.0.0" }] },
  ])("malformed event stream is unknown, not exclusion: %j", ({ events }) => {
    expect(status("1.0.0", [range(events)])).toBe("unknown");
  });

  it("unsupported ranges, ecosystems and invalid versions cannot prove exclusion", () => {
    expect(status("1.0.0", [{ type: "GIT", events: [{ introduced: "0" }, { fixed: "deadbeef" }] }])).toBe("unknown");
    expect(status("not-a-version", [range([{ introduced: "0" }, { fixed: "2.0.0" }])])).toBe("unknown");
    expect(osvVersionStatus([{ package: { ecosystem: "PyPI", name: "pkg" }, ranges: [range([{ introduced: "0" }, { fixed: "2.0.0" }])] }], "PyPI", "pkg", "3.0.0")).toBe("unknown");
    expect(osvVersionStatus([], "npm", "pkg", "1.0.0")).toBe("unknown");
  });

  it("a proven hit wins; exclusion requires every applicable range to be understood", () => {
    const ranges = [{ type: "ECOSYSTEM", events: [{ introduced: "0" }] }, range([{ introduced: "0" }, { fixed: "2.0.0" }])];
    expect(status("1.0.0", ranges)).toBe("affected");
    expect(status("3.0.0", ranges)).toBe("unknown");
    expect(status("1.0.0", [], ["1.0.0"])).toBe("affected");
    expect(status("2.0.0", [], ["1.0.0"])).toBe("outside");
    expect(status("2.0.0", [])).toBe("unknown");
  });
});
