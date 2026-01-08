import { Instance } from "@/project/instance"
import { Log } from "@/util/log"
import { Policy } from "./engine"
import { PolicyInput } from "./input"
import z from "zod"
import path from "node:path"

export namespace PolicyAudit {
  const log = Log.create({ service: "policy.audit" })

  export const Entry = z
    .object({
      ts: z.string(),
      session: z.string(),
      permission: z.string(),
      pattern: z.string(),
      decision: Policy.Decision,
      duration_ms: z.number(),
      policy: z.string().optional(),
      input: PolicyInput.Schema.optional(),
    })
    .meta({ ref: "PolicyAuditEntry" })
  export type Entry = z.infer<typeof Entry>

  export interface Options {
    enabled?: boolean
    path?: string
    include_input?: boolean
  }

  let options: Options = {
    enabled: true,
    path: ".opencode/audit.jsonl",
    include_input: false,
  }

  export function configure(opts: Options): void {
    options = { ...options, ...opts }
  }

  export async function write(
    input: PolicyInput.Schema,
    decision: Policy.Decision,
    durationMs?: number,
    policyName?: string,
  ): Promise<void> {
    if (options.enabled === false) return

    const entry: Entry = {
      ts: new Date().toISOString(),
      session: input.session.id,
      permission: input.permission,
      pattern: input.pattern,
      decision,
      duration_ms: durationMs ?? 0,
      policy: policyName,
    }

    // Optionally include full input (privacy consideration)
    if (options.include_input) {
      entry.input = input
    }

    const auditPath = options.path ?? ".opencode/audit.jsonl"
    const project = Instance.project

    try {
      const fullPath = path.join(project.worktree, auditPath)

      // Ensure directory exists
      const dir = path.dirname(fullPath)
      await Bun.write(path.join(dir, ".keep"), "")

      // Append to audit log
      const file = Bun.file(fullPath)
      const existing = (await file.exists()) ? await file.text() : ""
      await Bun.write(fullPath, existing + JSON.stringify(entry) + "\n")
    } catch (err) {
      log.warn("failed to write audit log", { error: err })
    }
  }

  export async function read(opts?: { last?: number; denied?: boolean }): Promise<Entry[]> {
    const auditPath = options.path ?? ".opencode/audit.jsonl"
    const project = Instance.project
    const fullPath = path.join(project.worktree, auditPath)

    try {
      const file = Bun.file(fullPath)
      if (!(await file.exists())) return []

      const content = await file.text()
      const lines = content.trim().split("\n").filter(Boolean)

      let entries = lines.map((line) => JSON.parse(line) as Entry)

      if (opts?.denied) {
        entries = entries.filter((e) => e.decision.deny || (e.decision.reasons && e.decision.reasons.length > 0))
      }

      if (opts?.last) {
        entries = entries.slice(-opts.last)
      }

      return entries
    } catch (err) {
      log.warn("failed to read audit log", { error: err })
      return []
    }
  }
}
