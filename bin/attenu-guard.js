#!/usr/bin/env node
"use strict";
const { main } = require("../dist/cjs/cli.js");
process.exitCode = main(process.argv.slice(2));
