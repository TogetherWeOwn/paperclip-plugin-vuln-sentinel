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

  it.each(["v2.0.0", " 2.0.0", "2.0.0 ", "=2.0.0", "2.0", "02.0.0", "2.0.0-01"])(
    "does not normalize a noncanonical installed version into exclusion: %s", version => {
      expect(status(version, [range([{ introduced: "0" }, { fixed: "1.0.0" }])])).toBe("unknown");
    },
  );

  it.each(["v1.0.0", " 1.0.0 ", "=1.0.0", "1.0", "01.0.0", "1.0.0-01"])(
    "does not normalize a noncanonical advisory boundary into exclusion: %s", fixed => {
      expect(status("2.0.0", [range([{ introduced: "0" }, { fixed }])])).toBe("unknown");
    },
  );

  it("does not accept mixed fixed and last_affected as a valid exclusion proof", () => {
    expect(status("4.0.0", [range([
      { introduced: "0" }, { fixed: "1.0.0" }, { introduced: "2.0.0" }, { last_affected: "3.0.0" },
    ])])).toBe("unknown");
  });

  it("treats limits as range-wide bounds, not interval endings", () => {
    const bounded = [range([
      { introduced: "0" }, { limit: "1.0.0" }, { fixed: "2.0.0" },
      { introduced: "3.0.0" }, { fixed: "4.0.0" },
    ])];
    expect(status("0.5.0", bounded)).toBe("affected");
    expect(status("1.5.0", bounded)).toBe("outside");
    expect(status("3.5.0", bounded)).toBe("outside");
  });

  it("accepts any limit, including infinity, independently of event storage position", () => {
    const events = [{ limit: "1.0.0" }, { introduced: "0" }, { fixed: "2.0.0" }, { limit: "3.0.0" }];
    expect(status("1.5.0", [range(events)])).toBe("affected");
    expect(status("2.5.0", [range(events)])).toBe("outside");
    expect(status("3.0.0", [range([{ introduced: "0" }, { limit: "3.0.0" }])])).toBe("outside");
    expect(status("9.0.0", [range([{ introduced: "0" }, { limit: "*" }])])).toBe("affected");
    expect(status("9.0.0", [range([{ limit: "*" }, { introduced: "0" }, { limit: "1.0.0" }])])).toBe("affected");
  });

  it("validates the whole stream before using a limit for exclusion", () => {
    expect(status("9.0.0", [range([{ fixed: "1.0.0" }, { limit: "2.0.0" }])])).toBe("unknown");
    expect(status("9.0.0", [range([{ introduced: "0" }, { limit: "v2.0.0" }])])).toBe("unknown");
  });

  it("uses SemVer precedence for prereleases and ignores build metadata", () => {
    const bounded = [range([{ introduced: "1.0.0-alpha.2+start" }, { fixed: "1.0.0+fix" }])];
    expect(status("1.0.0-alpha.1", bounded)).toBe("outside");
    expect(status("1.0.0-alpha.2+other", bounded)).toBe("affected");
    expect(status("1.0.0-beta.1", bounded)).toBe("affected");
    expect(status("1.0.0+installed", bounded)).toBe("outside");
    expect(status("0.0.0-0", [range([{ introduced: "0" }])])).toBe("affected");
  });

  it.each(["v1.0.0", " 1.0.0 ", "1.0", "1.0.0-01"])(
    "does not use malformed npm version enumeration to prove exclusion: %s", value => {
      expect(status("2.0.0", [], [value])).toBe("unknown");
      expect(status(value, [], ["2.0.0"])).toBe("unknown");
      expect(status(value, [], [value])).toBe("affected");
      expect(status("2.0.0", [range([{ introduced: "0" }, { fixed: "1.0.0" }])], [value])).toBe("unknown");
    },
  );

  it("keeps positive enumeration/ranges additive even alongside invalid evidence", () => {
    expect(status("1.0.0", [range([{ introduced: "0" }, { fixed: "v2.0.0" }])], ["1.0.0"])).toBe("affected");
    expect(status("1.0.0", [range([{ introduced: "0" }, { fixed: "2.0.0" }])], ["v1.0.0"])).toBe("affected");
    expect(status("1.0.0", [range([{ introduced: "0" }, { limit: "1.0.0" }])], ["1.0.0"])).toBe("affected");
  });

  it("rejects missing introductions, misplaced sentinels and malformed limits", () => {
    for (const events of [
      [{ limit: "2.0.0" }], [{ limit: "*" }], [{ introduced: "*" }],
      [{ introduced: "0" }, { limit: "0" }], [{ introduced: "0" }, { fixed: "*" }],
      [{ introduced: "0" }, { limit: "2.*" }], [{ introduced: "0" }, { limit: "" }],
      [{ introduced: "0" }, { fixed: "1.0.0" }, { introduced: "0" }],
    ]) expect(status("9.0.0", [range(events)])).toBe("unknown");
  });

  it("matches interval union and range-wide any-limit semantics over a boundary grid", () => {
    for (let start = 1; start <= 3; start++) {
      for (let end = start + 1; end <= 5; end++) {
        for (let upper = 1; upper <= 6; upper++) {
          for (let candidate = 0; candidate <= 7; candidate++) {
            const events = [{ introduced: `${start}.0.0` }, { fixed: `${end}.0.0` },
              { introduced: "6.0.0" }, { limit: `${upper}.0.0` }, { limit: "2.0.0" }];
            const expected = (candidate >= start && candidate < end || candidate >= 6)
              && (candidate < upper || candidate < 2);
            expect(status(`${candidate}.0.0`, [range(events)])).toBe(expected ? "affected" : "outside");
          }
        }
      }
    }
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
