import { Plugin } from "../plugin"
import { Format } from "../format"
import { LSP } from "../lsp"
import { File } from "../file"
import { FileWatcher } from "../file/watcher"
import { Snapshot } from "../snapshot"
import { Project } from "./project"
import { Vcs } from "./vcs"
import { Bus } from "../bus"
import { Command } from "../command"
import { Instance } from "./instance"
import { Log } from "@/util/log"
import { ShareNext } from "@/share/share-next"
import { PolicyLoader } from "@/policy"
import { Config } from "@/config/config"
import { Permission } from "@/permission"

export async function InstanceBootstrap() {
  Log.Default.info("bootstrapping", { directory: Instance.directory })
  await Plugin.init()
  ShareNext.init()
  Format.init()
  await LSP.init()
  File.init()
  FileWatcher.init()
  Vcs.init()
  Snapshot.init()

  const config = await Config.get()
  if (config.policy?.enabled) {
    await PolicyLoader.init(config.policy ?? {}).catch((err) => {
      Log.Default.warn("policy engine initialization failed", { error: err })
    })
    Permission.setPolicyEnabled(true)
  }

  Bus.subscribe(Command.Event.Executed, async (payload) => {
    if (payload.properties.name === Command.Default.INIT) {
      Project.setInitialized(Instance.project.id)
    }
  })
}
