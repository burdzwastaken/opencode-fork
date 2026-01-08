import { Instance } from "@/project/instance"
import { Session } from "@/session"
import { SessionID } from "@/session/schema"
import { Log } from "@/util/log"
import z from "zod"

export namespace PolicyInput {
  const log = Log.create({ service: "policy.input" })

  export const Schema = z
    .object({
      permission: z.string(),
      pattern: z.string(),
      metadata: z.record(z.string(), z.unknown()),
      session: z.object({
        id: z.string(),
        agent: z.string(),
        user: z.string().optional(),
        message_count: z.number(),
        tool_calls: z.number(),
        start_time: z.string(),
      }),
      environment: z.object({
        cwd: z.string(),
        git_branch: z.string().optional(),
        git_remote: z.string().optional(),
        time: z.string(),
        day_of_week: z.number(),
        hour: z.number(),
        ci: z.boolean().optional(),
      }),
      history: z.object({
        recent_permissions: z.string().array(),
        recent_patterns: z.string().array(),
        recent_paths: z.string().array(),
        denied_count: z.number(),
        approved_count: z.number(),
      }),
    })
    .meta({ ref: "PolicyInput" })

  export type Schema = z.infer<typeof Schema>

  export async function build(input: {
    permission: string
    pattern: string
    sessionID: string
    metadata: Record<string, unknown>
  }): Promise<Schema> {
    const project = Instance.project
    const sid = SessionID.make(input.sessionID)
    const session = await Session.get(sid).catch(() => null)
    const messages = session
      ? await Session.messages({ sessionID: sid }).catch(() => [])
      : []

    const toolCalls = messages.filter((m) => {
      const info = m.info as Record<string, unknown>
      return info.tool_calls || info.tool_call_id
    }).length

    // Build history from recent messages
    const recentMessages = messages.slice(-50)
    const recentPermissions: string[] = []
    const recentPatterns: string[] = []
    const recentPaths: string[] = []
    let deniedCount = 0
    let approvedCount = 0

    for (const msg of recentMessages) {
      const info = msg.info as Record<string, unknown>
      const meta = info.metadata as Record<string, unknown> | undefined
      if (!meta) continue
      if (meta.permission) recentPermissions.push(meta.permission as string)
      if (meta.pattern) recentPatterns.push(meta.pattern as string)
      if (meta.path) recentPaths.push(meta.path as string)
      if (meta.action === "deny") deniedCount++
      if (meta.action === "allow") approvedCount++
    }

    const now = new Date()
    const sessionInfo = session as Record<string, unknown> | null
    const sessionTime = sessionInfo?.time as Record<string, unknown> | undefined
    const startTime = sessionTime?.created
      ? new Date(sessionTime.created as number).toISOString()
      : now.toISOString()

    return {
      permission: input.permission,
      pattern: input.pattern,
      metadata: input.metadata,
      session: {
        id: input.sessionID,
        agent: (sessionInfo?.agent as string) ?? "coder",
        user: process.env.USER,
        message_count: messages.length,
        tool_calls: toolCalls,
        start_time: startTime,
      },
      environment: {
        cwd: project.worktree,
        git_branch: undefined, // Git info not directly available on project
        git_remote: undefined,
        time: now.toISOString(),
        day_of_week: now.getDay(),
        hour: now.getHours(),
        ci: !!process.env.CI || !!process.env.OPENCODE_CI,
      },
      history: {
        recent_permissions: recentPermissions.slice(-20),
        recent_patterns: recentPatterns.slice(-20),
        recent_paths: recentPaths.slice(-30),
        denied_count: deniedCount,
        approved_count: approvedCount,
      },
    }
  }
}
