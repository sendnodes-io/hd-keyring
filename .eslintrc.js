module.exports = {
  root: true,
  extends: [
    "plugin:import/typescript",
    "plugin:@typescript-eslint/recommended",
    "plugin:prettier/recommended",
  ],
  parserOptions: {
    project: "./.tsconfig-eslint.json",
  },
  ignorePatterns: ["dist/*", "hdnode/*", "signing-key/*"],
};
