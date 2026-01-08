import { fileURLToPath } from "node:url"
import { Instance } from "@/project/instance"
import { Log } from "@/util/log"
import z from "zod"

export namespace Policy {
  const log = Log.create({ service: "policy" })

  // Buffer constants matching wasm_main.zig
  const IO_BUFFER_SIZE = 4 * 1024 * 1024 // 4MB
  const RESULT_BUFFER_SIZE = 1 * 1024 * 1024 // 1MB

  // Error codes from wasm_main.zig
  export const ErrorCode = {
    SUCCESS: 0,
    NOT_INITIALIZED: -1,
    BUFFER_OVERFLOW: -2,
    NOT_FOUND: -3,
    OPERATION_FAILED: -4,
    OUT_OF_MEMORY: -5,
  } as const

  export const Decision = z
    .object({
      allow: z.boolean().optional(),
      deny: z.boolean().optional(),
      defer: z.boolean().optional(),
      ask: z.boolean().optional(),
      reasons: z.string().array().optional(),
      message: z.string().optional(),
      suggestions: z.string().array().optional(),
    })
    .meta({ ref: "PolicyDecision" })
  export type Decision = z.infer<typeof Decision>

  interface WasmExports {
    memory: WebAssembly.Memory
    init: () => number
    deinit: () => void
    reset: () => void
    loadPolicy: (namePtr: number, nameLen: number, wasmPtr: number, wasmLen: number) => number
    unloadPolicy: (namePtr: number, nameLen: number) => number
    setData: (namePtr: number, nameLen: number, dataPtr: number, dataLen: number) => number
    evaluate: (
      namePtr: number,
      nameLen: number,
      epPtr: number,
      epLen: number,
      inputPtr: number,
      inputLen: number,
    ) => number
    getLoadedPolicies: () => number
    getEntrypoints: (namePtr: number, nameLen: number) => number
    getIOBuffer: () => number
    getIOBufferSize: () => number
    getResultBuffer: () => number
    getResultLen: () => number
  }

  interface EngineState {
    instance: WebAssembly.Instance
    exports: WasmExports
    ioBuffer: Uint8Array
    resultBuffer: Uint8Array
  }

  const resolveWasm = (asset: string) => {
    if (asset.startsWith("file://")) return fileURLToPath(asset)
    if (asset.startsWith("/") || /^[a-z]:/i.test(asset)) return asset
    const url = new URL(asset, import.meta.url)
    return fileURLToPath(url)
  }

  let engineState: EngineState | null = null
  let initPromise: Promise<EngineState> | null = null

  async function initEngine(): Promise<EngineState> {
    if (engineState) return engineState
    if (initPromise) return initPromise

    initPromise = (async () => {
      try {
        const { default: policyWasm } = await import("../../wasm/zig-opa-wasm.wasm" as string, {
          with: { type: "wasm" },
        })

        const wasmPath = resolveWasm(policyWasm)
        const wasmBytes = await Bun.file(wasmPath).arrayBuffer()

        const { instance } = await WebAssembly.instantiate(wasmBytes, {
          env: {},
        })

        const exports = instance.exports as unknown as WasmExports

        const initResult = exports.init()
        if (initResult !== 0) {
          throw new Error(`Failed to initialize policy engine: ${initResult}`)
        }

        const ioPtr = exports.getIOBuffer()
        const resultPtr = exports.getResultBuffer()
        const memory = exports.memory

        const ioBuffer = new Uint8Array(memory.buffer, ioPtr, IO_BUFFER_SIZE)
        const resultBuffer = new Uint8Array(memory.buffer, resultPtr, RESULT_BUFFER_SIZE)

        engineState = { instance, exports, ioBuffer, resultBuffer }
        log.info("policy engine initialized")

        return engineState
      } catch (err) {
        initPromise = null
        throw err
      }
    })()

    return initPromise
  }

  function writeToBuffer(state: EngineState, data: string, offset: number): number {
    const encoded = new TextEncoder().encode(data)
    if (offset + encoded.length > IO_BUFFER_SIZE) {
      throw new Error("Buffer overflow: data too large for I/O buffer")
    }
    state.ioBuffer.set(encoded, offset)
    return encoded.length
  }

  function writeBytes(state: EngineState, data: Uint8Array, offset: number): number {
    if (offset + data.length > IO_BUFFER_SIZE) {
      throw new Error("Buffer overflow: data too large for I/O buffer")
    }
    state.ioBuffer.set(data, offset)
    return data.length
  }

  function readResult(state: EngineState): string {
    const len = state.exports.getResultLen()
    const decoder = new TextDecoder()
    return decoder.decode(state.resultBuffer.slice(0, len))
  }

  function checkResult(state: EngineState, code: number, operation: string): void {
    if (code >= 0) return
    const message = readResult(state)
    throw new Error(`${operation} failed (${code}): ${message}`)
  }

  export async function isInitialized(): Promise<boolean> {
    return engineState !== null
  }

  export async function load(name: string, wasmBytes: Uint8Array): Promise<void> {
    const state = await initEngine()

    const nameLen = writeToBuffer(state, name, 0)
    const wasmOffset = nameLen
    writeBytes(state, wasmBytes, wasmOffset)

    const result = state.exports.loadPolicy(0, nameLen, wasmOffset, wasmBytes.length)
    checkResult(state, result, "loadPolicy")
    log.info("loaded policy", { name })
  }

  export async function unload(name: string): Promise<void> {
    const state = await initEngine()
    const nameLen = writeToBuffer(state, name, 0)
    const result = state.exports.unloadPolicy(0, nameLen)
    checkResult(state, result, "unloadPolicy")
    log.info("unloaded policy", { name })
  }

  export async function setData(name: string, data: unknown): Promise<void> {
    const state = await initEngine()
    const dataJson = JSON.stringify(data)
    const nameLen = writeToBuffer(state, name, 0)
    const dataOffset = nameLen
    const dataLen = writeToBuffer(state, dataJson, dataOffset)

    const result = state.exports.setData(0, nameLen, dataOffset, dataLen)
    checkResult(state, result, "setData")
  }

  export async function evaluate(name: string, entrypoint: string, input: unknown): Promise<Decision> {
    const state = await initEngine()
    const inputJson = JSON.stringify(input)

    let offset = 0
    const nameLen = writeToBuffer(state, name, offset)
    offset += nameLen

    const epOffset = offset
    const epLen = writeToBuffer(state, entrypoint, offset)
    offset += epLen

    const inputOffset = offset
    const inputLen = writeToBuffer(state, inputJson, offset)

    const result = state.exports.evaluate(0, nameLen, epOffset, epLen, inputOffset, inputLen)
    if (result < 0) {
      checkResult(state, result, "evaluate")
    }

    const resultJson = readResult(state)
    const parsed = JSON.parse(resultJson)

    // OPA returns [{result: {...}}] format - unwrap it
    if (Array.isArray(parsed) && parsed.length > 0 && parsed[0].result) {
      return parsed[0].result as Decision
    }
    return parsed as Decision
  }

  export async function getLoadedPolicies(): Promise<string[]> {
    const state = await initEngine()
    const result = state.exports.getLoadedPolicies()
    if (result < 0) {
      checkResult(state, result, "getLoadedPolicies")
    }
    const json = readResult(state)
    return JSON.parse(json) as string[]
  }

  export async function getEntrypoints(name: string): Promise<string[]> {
    const state = await initEngine()
    const nameLen = writeToBuffer(state, name, 0)
    const result = state.exports.getEntrypoints(0, nameLen)
    if (result < 0) {
      checkResult(state, result, "getEntrypoints")
    }
    const json = readResult(state)
    return JSON.parse(json) as string[]
  }

  export async function reset(): Promise<void> {
    if (!engineState) return
    engineState.exports.reset()
    log.info("policy engine reset")
  }

  export async function shutdown(): Promise<void> {
    if (!engineState) return
    engineState.exports.deinit()
    engineState = null
    initPromise = null
    log.info("policy engine shutdown")
  }
}
