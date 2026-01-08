#!/usr/bin/env bun
import { $ } from "bun"
import { readdir } from "node:fs/promises"
import path from "node:path"

const POLICY_DIR = "src/policy/defaults"

async function buildPolicies() {
  const files = await readdir(POLICY_DIR)
  const regoFiles = files.filter((f) => f.endsWith(".rego"))

  if (regoFiles.length === 0) {
    console.log("No .rego files found in", POLICY_DIR)
    return
  }

  for (const rego of regoFiles) {
    const name = rego.replace(".rego", "")
    const regoPath = path.join(POLICY_DIR, rego)
    const wasmPath = path.join(POLICY_DIR, `${name}.wasm`)

    console.log(`Compiling ${rego} → ${name}.wasm`)

    await $`opa build -t wasm -e "opencode/permissions/${name}/result" -o /tmp/${name}.tar.gz ${regoPath}`
    await $`tar -xzf /tmp/${name}.tar.gz -C /tmp policy.wasm`
    await $`mv /tmp/policy.wasm ${wasmPath}`

    console.log(`  ${wasmPath}`)
  }

  console.log("Done!")
}

buildPolicies().catch((err) => {
  console.error("Build failed:", err)
  process.exit(1)
})
