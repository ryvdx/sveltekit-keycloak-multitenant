// import resolve from "@rollup/plugin-node-resolve";
import commonjs from "@rollup/plugin-commonjs";
import typescript from "@rollup/plugin-typescript";
import pkg from "./package.json" assert {type: 'json'};
import terser from '@rollup/plugin-terser';

export default [

  // CommonJS (for Node) and ES module (for bundlers) build.
  // (We could have three entries in the configuration array
  // instead of two, but it's quicker to generate multiple
  // builds from a single configuration where possible, using
  // an array for the `output` option, where we can specify
  // `file` and `format` for each target)
  {
    input: "src/keycloakservice.ts",
    // external: [],
    plugins: [
        // svelte({ emitCss: false }),
        // resolve(),
        commonjs(),
        typescript(), // so Rollup can convert TypeScript to JavaScript
        terser()
    ],
    output: [
      { file: pkg.main, format: "cjs" },
      { file: pkg.module, format: "es" },
    ],
  },
];
