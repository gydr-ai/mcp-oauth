// @ts-check
import vitest from "@vitest/eslint-plugin"
import jsdoc from "eslint-plugin-jsdoc"
import tseslint from "typescript-eslint"

export default tseslint.config(
  { ignores: ["dist/", "coverage/"] },
  ...tseslint.configs.strictTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    linterOptions: { reportUnusedDisableDirectives: "error" },
    rules: {
      eqeqeq: ["error", "always"],
      "no-else-return": ["error", { allowElseIf: false }],
      "no-eval": "error",
      "no-new-func": "error",
      "no-param-reassign": "error",
      "prefer-const": "error",
      "@typescript-eslint/consistent-type-imports": "error",
      "@typescript-eslint/switch-exhaustiveness-check": "error",
      "@typescript-eslint/restrict-template-expressions": [
        "error",
        { allowNumber: true },
      ],
    },
  },
  {
    files: ["src/**/*.ts"],
    ...jsdoc.configs["flat/recommended-typescript-error"],
  },
  {
    files: ["src/**/*.ts"],
    rules: {
      "jsdoc/require-jsdoc": [
        "error",
        {
          publicOnly: true,
          require: {
            FunctionDeclaration: true,
            ClassDeclaration: true,
            MethodDefinition: true,
            ArrowFunctionExpression: false,
          },
        },
      ],
      "jsdoc/no-undefined-types": "off",
      // A blank line between the description and the tags, none required between tags.
      "jsdoc/tag-lines": ["error", "any", { startLines: 1 }],
    },
  },
  {
    files: ["test/**/*.ts"],
    plugins: { vitest },
    rules: {
      ...vitest.configs.recommended.rules,
      // Tests narrow caught errors and parsed JSON on purpose.
      "@typescript-eslint/no-unsafe-type-assertion": "off",
      "@typescript-eslint/no-non-null-assertion": "off",
    },
  },
  {
    files: ["*.config.{js,ts}", "scripts/**/*.mjs"],
    ...tseslint.configs.disableTypeChecked,
  },
)
