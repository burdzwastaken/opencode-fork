import { fileURLToPath } from "node:url"
import { readdir } from "node:fs/promises"
import path from "node:path"
import { Policy } from "./engine"
import { PolicyAudit } from "./audit"
import { Log } from "@/util/log"

export namespace PolicyLoader {
  const log = Log.create({ service: "policy.loader" })

  export interface Config {
    enabled?: boolean
    policyName?: string
    sources?: string[]
    disable?: string[]
    data?: Record<string, unknown>
    audit?: {
      enabled?: boolean
      path?: string
      include_input?: boolean
    }
    mode?: "enforce" | "audit"
    on_error?: "deny" | "allow" | "ask"
  }

  const resolveWasm = (asset: string) => {
    if (asset.startsWith("file://")) return fileURLToPath(asset)
    if (asset.startsWith("/") || /^[a-z]:/i.test(asset)) return asset
    const url = new URL(asset, import.meta.url)
    return fileURLToPath(url)
  }

  export async function init(config: Config): Promise<void> {
    if (config.enabled === false) {
      log.info("policy engine disabled")
      return
    }

    if (config.audit) {
      PolicyAudit.configure(config.audit)
    }

    const disabled = new Set(config.disable ?? [])

    const sources = config.sources ?? ["builtin:default", "~/.config/opencode/policies/", ".opencode/policies/"]

    for (const source of sources) {
      if (disabled.has(source)) continue

      if (source === "builtin:default") {
        await loadBuiltinDefaults()
        continue
      }

      const expandedPath = source.replace("~", process.env.HOME ?? "")
      await loadFromDirectory(expandedPath)
    }

    if (config.data) {
      const policyName = config.policyName ?? "opencode"
      await Policy.setData(policyName, config.data)
    }

    const loaded = await Policy.getLoadedPolicies()
    log.info("policy engine initialized", {
      policies: loaded,
      mode: config.mode ?? "enforce",
    })
  }

  async function loadBuiltinDefaults(): Promise<void> {
    const defaultsDir = new URL("./defaults/", import.meta.url)

    try {
      const dirPath = fileURLToPath(defaultsDir)
      await loadFromDirectory(dirPath)
    } catch (err) {
      log.debug("no bundled default policies found", { error: err })
    }
  }

  async function loadFromDirectory(dir: string): Promise<void> {
    try {
      const files = await readdir(dir)

      for (const file of files) {
        if (!file.endsWith(".wasm")) continue

        const name = file.replace(".wasm", "")
        const filePath = path.join(dir, file)
        const wasmBytes = await Bun.file(filePath).arrayBuffer()
        await Policy.load(name, new Uint8Array(wasmBytes))
        log.info("loaded policy", { name, path: dir })
      }
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code
      if (code !== "ENOENT") {
        log.warn("failed to load policies", { dir, error: err })
      }
    }
  }

  export async function loadPolicy(name: string, wasmPath: string): Promise<void> {
    const wasmBytes = await Bun.file(wasmPath).arrayBuffer()
    await Policy.load(name, new Uint8Array(wasmBytes))
    log.info("loaded policy", { name, path: wasmPath })
  }

  export async function loadPolicyBytes(name: string, wasmBytes: Uint8Array): Promise<void> {
    await Policy.load(name, wasmBytes)
    log.info("loaded policy", { name })
  }
}
