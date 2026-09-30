// Node 的 ESM 解析器要求显式扩展名，而 jsencrypt 的 lib/*.js 使用无扩展名相对导入
// （浏览器打包器可以解析，裸 Node 不行）。这里补一个解析钩子，仅用于测试脚本。
import { existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

export async function resolve (specifier, context, next) {
  try {
    return await next(specifier, context)
  } catch (e) {
    if (e.code === 'ERR_MODULE_NOT_FOUND' && (specifier.startsWith('./') || specifier.startsWith('../'))) {
      const base = new URL(specifier, context.parentURL)
      for (const suffix of ['.js', '/index.js', '.mjs', '.cjs']) {
        const candidate = new URL(base.href + suffix)
        if (existsSync(fileURLToPath(candidate))) {
          return { url: candidate.href, shortCircuit: true }
        }
      }
    }
    throw e
  }
}
