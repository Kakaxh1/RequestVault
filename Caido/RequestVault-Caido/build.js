/**
 * RequestVault for Caido - Build and Packaging Script
 * Bundles TypeScript sources via esbuild and creates the final distributable Caido plugin ZIP.
 *
 * Author: Kakaxh1 (https://bhavymorvadiya.netlify.app/)
 */

const esbuild = require("esbuild");
const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

async function build() {
  console.log("================================================================");
  console.log("  RequestVault for Caido - Build & Package");
  console.log("  Author:  Kakaxh1");
  console.log("  Website: https://bhavymorvadiya.netlify.app/");
  console.log("================================================================\n");

  const distDir = path.resolve(__dirname, "dist");
  if (!fs.existsSync(distDir)) {
    fs.mkdirSync(distDir, { recursive: true });
  }

  console.log("[1/3] Bundling TypeScript plugin with esbuild...");
  await esbuild.build({
    entryPoints: [path.resolve(__dirname, "src/index.ts")],
    bundle: true,
    outfile: path.resolve(distDir, "script.js"),
    format: "esm",
    target: "es2022",
    platform: "browser",
    minify: false,
    sourcemap: false
  });
  console.log("      Output generated at dist/script.js");

  console.log("[2/3] Copying manifest.json...");
  const manifestSrc = path.resolve(__dirname, "manifest.json");
  const manifestDest = path.resolve(distDir, "manifest.json");
  fs.copyFileSync(manifestSrc, manifestDest);
  console.log("      Copied manifest.json to dist/manifest.json");

  console.log("[3/3] Creating Caido plugin ZIP archive...");
  const zipPath = path.resolve(distDir, "requestvault-caido.zip");
  if (fs.existsSync(zipPath)) {
    fs.unlinkSync(zipPath);
  }

  // Use PowerShell Compress-Archive for fast, native Windows packaging
  const cmd = `powershell -NoProfile -Command "Compress-Archive -Path '${path.resolve(distDir, "manifest.json")}', '${path.resolve(distDir, "script.js")}' -DestinationPath '${zipPath}' -Force"`;
  execSync(cmd, { stdio: "inherit" });

  const stats = fs.statSync(zipPath);
  console.log("\n================================================================");
  console.log(" [SUCCESS] Build Finished Successfully.");
  console.log(` Artifact: dist/requestvault-caido.zip (${(stats.size / 1024).toFixed(1)} KB)`);
  console.log(" Website:  https://bhavymorvadiya.netlify.app/");
  console.log("================================================================");
  console.log("You can now install dist/requestvault-caido.zip directly into Caido via:");
  console.log("Caido -> Plugins -> Install from File -> Select requestvault-caido.zip\n");
}

build().catch((err) => {
  console.error("[ERROR] Build failed:", err);
  process.exit(1);
});
