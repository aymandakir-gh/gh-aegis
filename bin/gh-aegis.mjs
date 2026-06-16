#!/usr/bin/env node
// gh-aegis CLI entry point. Delegates to the compiled scanner in dist/.
import { run } from "../dist/cli.js";

run(process.argv.slice(2))
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error(err);
    process.exit(2);
  });
