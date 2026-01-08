#!/usr/bin/env bun
import { Policy } from "./src/policy/engine"
import { PolicyLoader } from "./src/policy/loader"

async function testPolicyEngine() {
  console.log("=== Testing zig-opa-wasm Policy Engine ===\n")

  console.log("1. Loading builtin policies via PolicyLoader...")
  await PolicyLoader.init({
    enabled: true,
    sources: ["builtin:default"],
    mode: "enforce",
  })

  const policies = await Policy.getLoadedPolicies()
  console.log(`   Loaded policies: ${JSON.stringify(policies)}`)

  if (policies.length === 0) {
    console.log("   No policies loaded!")
    return
  }
  console.log("   Policies loaded\n")

  console.log("2. Testing bash policy - safe command (ls -la)...")
  const safeInput = {
    permission: "bash",
    pattern: "ls -la",
    metadata: { command: "ls -la" },
    session: { id: "test", agent: "coder", message_count: 1, tool_calls: 0, start_time: new Date().toISOString() },
    environment: { cwd: "/tmp", time: new Date().toISOString(), day_of_week: 3, hour: 14 },
    history: { recent_permissions: [], recent_patterns: [], recent_paths: [], denied_count: 0, approved_count: 0 },
  }

  try {
    const decision = await Policy.evaluate("bash", "opencode/permissions/bash/result", safeInput)
    console.log(`   Decision: allow=${decision.allow}, deny=${decision.deny}`)
    if (decision.allow) {
      console.log("   Safe command ALLOWED\n")
    } else {
      console.log("   Safe command not allowed\n")
    }
  } catch (err) {
    console.log(`   Error: ${err}\n`)
  }

  console.log("3. Testing bash policy - dangerous command (sudo rm -rf /)...")
  const dangerousInput = {
    ...safeInput,
    pattern: "sudo rm -rf /",
    metadata: { command: "sudo rm -rf /" },
  }

  try {
    const decision = await Policy.evaluate("bash", "opencode/permissions/bash/result", dangerousInput)
    console.log(`   Decision: allow=${decision.allow}, deny=${decision.deny}`)
    if (decision.deny) {
      console.log(`   Dangerous command DENIED: ${decision.reasons?.join("; ")}\n`)
    } else {
      console.log("   Dangerous command not denied\n")
    }
  } catch (err) {
    console.log(`   Error: ${err}\n`)
  }

  console.log("4. Testing bash policy - npm install...")
  const npmInput = {
    ...safeInput,
    pattern: "npm install",
    metadata: { command: "npm install express" },
  }

  try {
    const decision = await Policy.evaluate("bash", "opencode/permissions/bash/result", npmInput)
    console.log(`   Decision: allow=${decision.allow}, deny=${decision.deny}`)
    if (decision.allow) {
      console.log("   Dev command ALLOWED\n")
    } else {
      console.log("   Dev command not explicitly allowed\n")
    }
  } catch (err) {
    console.log(`   Error: ${err}\n`)
  }

  await Policy.shutdown()
  console.log("=== All tests completed ===")
}

testPolicyEngine().catch(console.error)
