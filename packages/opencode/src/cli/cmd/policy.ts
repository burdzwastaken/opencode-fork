import type { Argv } from "yargs"
import { EOL } from "os"
import { cmd } from "./cmd"
import { UI } from "../ui"
import { bootstrap } from "../bootstrap"
import { Policy, PolicyAudit } from "@/policy"

const ListCommand = cmd({
  command: "list",
  describe: "List loaded policies and entrypoints",
  handler: async () => {
    await bootstrap(process.cwd(), async () => {
      const policies = await Policy.getLoadedPolicies()
      if (policies.length === 0) {
        UI.println("No policies loaded")
        return
      }

      UI.println(UI.Style.TEXT_HIGHLIGHT_BOLD + "Loaded Policies" + UI.Style.TEXT_NORMAL)
      UI.empty()

      for (const name of policies) {
        const entrypoints = await Policy.getEntrypoints(name)
        UI.println(UI.Style.TEXT_HIGHLIGHT + name + UI.Style.TEXT_NORMAL)
        for (const entry of entrypoints) {
          UI.println("  " + UI.Style.TEXT_DIM + entry + UI.Style.TEXT_NORMAL)
        }
      }
    })
  },
})

const CheckCommand = cmd({
  command: "check <file>",
  describe: "Validate a policy file by loading it",
  builder: (yargs: Argv) =>
    yargs.positional("file", {
      type: "string",
      describe: "Path to .wasm policy file",
      demandOption: true,
    }),
  handler: async (args) => {
    const file = args.file as string
    const exists = await Bun.file(file).exists()
    if (!exists) {
      UI.error("File not found: " + file)
      process.exit(1)
    }

    if (!file.endsWith(".wasm")) {
      UI.error("Policy file must be a .wasm file")
      process.exit(1)
    }

    await bootstrap(process.cwd(), async () => {
      const name =
        file
          .replace(/\.wasm$/, "")
          .split("/")
          .pop() || "policy"
      const loaded = await Policy.getLoadedPolicies()
      const alreadyLoaded = loaded.includes(name)

      if (!alreadyLoaded) {
        const buffer = await Bun.file(file).arrayBuffer()
        const bytes = new Uint8Array(buffer)

        try {
          await Policy.load(name, bytes)
        } catch (err) {
          UI.error("Failed to load policy: " + (err as Error).message)
          process.exit(1)
        }
      }

      const entrypoints = await Policy.getEntrypoints(name)
      UI.println(UI.Style.TEXT_SUCCESS + "Policy valid: " + UI.Style.TEXT_NORMAL + name)
      UI.println("Entrypoints: " + entrypoints.join(", "))

      if (!alreadyLoaded) {
        await Policy.unload(name)
      }
    })
  },
})

const TestCommand = cmd({
  command: "test <file>",
  describe: "Test a policy with sample inputs",
  builder: (yargs: Argv) =>
    yargs
      .positional("file", {
        type: "string",
        describe: "Path to .wasm policy file",
        demandOption: true,
      })
      .option("input", {
        type: "string",
        alias: "i",
        describe: "JSON file with test inputs",
      })
      .option("entrypoint", {
        type: "string",
        alias: "e",
        describe: "Entrypoint to test",
      }),
  handler: async (args) => {
    const file = args.file as string
    const exists = await Bun.file(file).exists()
    if (!exists) {
      UI.error("File not found: " + file)
      process.exit(1)
    }

    await bootstrap(process.cwd(), async () => {
      const name =
        file
          .replace(/\.wasm$/, "")
          .split("/")
          .pop() || "policy"
      const loaded = await Policy.getLoadedPolicies()
      const alreadyLoaded = loaded.includes(name)

      if (!alreadyLoaded) {
        const buffer = await Bun.file(file).arrayBuffer()
        const bytes = new Uint8Array(buffer)

        try {
          await Policy.load(name, bytes)
        } catch (err) {
          UI.error("Failed to load policy: " + (err as Error).message)
          process.exit(1)
        }
      }

      const entrypoints = await Policy.getEntrypoints(name)
      const entrypoint = (args.entrypoint as string) || entrypoints[0]

      if (!entrypoint) {
        UI.error("No entrypoints found in policy")
        process.exit(1)
      }

      let inputs: Record<string, unknown>[] = []
      if (args.input) {
        const content = await Bun.file(args.input as string).text()
        const parsed = JSON.parse(content)
        inputs = Array.isArray(parsed) ? parsed : [parsed]
      } else {
        inputs = [
          { permission: "Bash", pattern: "ls -la", metadata: {} },
          { permission: "Bash", pattern: "rm -rf /", metadata: {} },
          { permission: "Bash", pattern: "sudo su", metadata: {} },
        ]
      }

      UI.println(UI.Style.TEXT_HIGHLIGHT_BOLD + "Testing: " + UI.Style.TEXT_NORMAL + name)
      UI.println("Entrypoint: " + entrypoint)
      UI.empty()

      let passed = 0
      let failed = 0

      for (const input of inputs) {
        const result = await Policy.evaluate(name, entrypoint, input)
        const status = result.allow
          ? UI.Style.TEXT_SUCCESS + "ALLOW" + UI.Style.TEXT_NORMAL
          : UI.Style.TEXT_DANGER + "DENY" + UI.Style.TEXT_NORMAL

        const pattern = (input.pattern as string) || JSON.stringify(input).slice(0, 50)
        UI.println(status + " " + pattern)

        if (result.reasons && result.reasons.length > 0) {
          for (const reason of result.reasons) {
            UI.println("  " + UI.Style.TEXT_DIM + reason + UI.Style.TEXT_NORMAL)
          }
        }

        if (result.allow) passed++
        else failed++
      }

      UI.empty()
      UI.println("Passed: " + passed + ", Failed: " + failed)

      if (!alreadyLoaded) {
        await Policy.unload(name)
      }
    })
  },
})

const AuditCommand = cmd({
  command: "audit",
  describe: "View policy decision audit log",
  builder: (yargs: Argv) =>
    yargs
      .option("limit", {
        type: "number",
        alias: "n",
        describe: "Number of entries to show",
        default: 20,
      })
      .option("json", {
        type: "boolean",
        describe: "Output as JSON",
        default: false,
      })
      .option("permission", {
        type: "string",
        alias: "p",
        describe: "Filter by permission type",
      }),
  handler: async (args) => {
    await bootstrap(process.cwd(), async () => {
      const entries = await PolicyAudit.read()

      if (entries.length === 0) {
        UI.println("No audit entries found")
        return
      }

      let filtered = entries
      if (args.permission) {
        filtered = entries.filter((e) => e.permission === args.permission)
      }

      const limited = filtered.slice(-(args.limit as number))

      if (args.json) {
        process.stdout.write(JSON.stringify(limited, null, 2) + EOL)
        return
      }

      UI.println(UI.Style.TEXT_HIGHLIGHT_BOLD + "Policy Audit Log" + UI.Style.TEXT_NORMAL)
      UI.println("Showing " + limited.length + " of " + filtered.length + " entries")
      UI.empty()

      for (const entry of limited) {
        const status = entry.decision.allow
          ? UI.Style.TEXT_SUCCESS + "ALLOW" + UI.Style.TEXT_NORMAL
          : UI.Style.TEXT_DANGER + "DENY" + UI.Style.TEXT_NORMAL

        const time = new Date(entry.ts).toLocaleTimeString()
        UI.println(
          UI.Style.TEXT_DIM + time + UI.Style.TEXT_NORMAL + " " + status + " " + entry.permission + " " + entry.pattern,
        )

        if (entry.decision.reasons && entry.decision.reasons.length > 0) {
          for (const reason of entry.decision.reasons) {
            UI.println("  " + UI.Style.TEXT_DIM + reason + UI.Style.TEXT_NORMAL)
          }
        }
      }
    })
  },
})

const ExplainCommand = cmd({
  command: "explain <permission> <pattern>",
  describe: "Explain why a command would be allowed or denied",
  builder: (yargs: Argv) =>
    yargs
      .positional("permission", {
        type: "string",
        describe: "Permission type (e.g., Bash, Edit)",
        demandOption: true,
      })
      .positional("pattern", {
        type: "string",
        describe: "Pattern to check (e.g., command or file path)",
        demandOption: true,
      }),
  handler: async (args) => {
    await bootstrap(process.cwd(), async () => {
      const permission = args.permission as string
      const pattern = args.pattern as string

      const input = {
        permission,
        pattern,
        metadata: {},
        session: {
          id: "explain",
          agent: "default",
          user: process.env.USER || "unknown",
          message_count: 0,
          tool_calls: 0,
          start_time: Date.now(),
        },
        environment: {
          cwd: process.cwd(),
          ci: !!process.env.CI,
        },
      }

      const policies = await Policy.getLoadedPolicies()
      if (policies.length === 0) {
        UI.println("No policies loaded")
        return
      }

      UI.println(UI.Style.TEXT_HIGHLIGHT_BOLD + "Policy Evaluation" + UI.Style.TEXT_NORMAL)
      UI.println("Permission: " + permission)
      UI.println("Pattern: " + pattern)
      UI.empty()

      for (const name of policies) {
        const entrypoints = await Policy.getEntrypoints(name)
        const entrypoint = entrypoints.find((e) => e.includes(permission.toLowerCase())) || entrypoints[0]

        if (!entrypoint) continue

        const result = await Policy.evaluate(name, entrypoint, input)
        const status = result.allow
          ? UI.Style.TEXT_SUCCESS + "ALLOW" + UI.Style.TEXT_NORMAL
          : UI.Style.TEXT_DANGER + "DENY" + UI.Style.TEXT_NORMAL

        UI.println(UI.Style.TEXT_HIGHLIGHT + name + UI.Style.TEXT_NORMAL + " -> " + status)

        if (result.reasons && result.reasons.length > 0) {
          UI.println("Reasons:")
          for (const reason of result.reasons) {
            UI.println("  - " + reason)
          }
        }

        if (result.message) {
          UI.println("Message: " + result.message)
        }

        if (result.suggestions && result.suggestions.length > 0) {
          UI.println("Suggestions:")
          for (const suggestion of result.suggestions) {
            UI.println("  - " + suggestion)
          }
        }
      }
    })
  },
})

export const PolicyCommand = cmd({
  command: "policy",
  describe: "Manage and inspect OPA policies",
  builder: (yargs: Argv) =>
    yargs
      .command(ListCommand)
      .command(CheckCommand)
      .command(TestCommand)
      .command(AuditCommand)
      .command(ExplainCommand)
      .demandCommand(1, "You must specify a subcommand"),
  handler: async () => {},
})
