// Tell Node how to read each build: the package is CommonJS by default, so the
// ESM output needs its own marker (and the CJS output an explicit one, in case
// the package type ever flips).
const { writeFileSync } = require("node:fs");
writeFileSync("dist/cjs/package.json", JSON.stringify({ type: "commonjs" }, null, 2) + "\n");
writeFileSync("dist/esm/package.json", JSON.stringify({ type: "module" }, null, 2) + "\n");
