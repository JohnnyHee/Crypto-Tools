/**
 * SSR 冒烟渲染：把所有 40 个导航 id 对应的组件真的渲染一遍。
 * 会执行 setup()、全部 computed 与模板渲染函数，能抓出「运行时才炸」的问题
 * （例如某个 computed 里调了不存在的函数、初始状态就抛异常）。
 *
 * 运行： node tests/ssr-render.mjs
 */
import { readFileSync } from 'node:fs'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createSSRApp } from 'vue'
import { renderToString } from 'vue/server-renderer'
import { createServer } from 'vite'
import vue from '@vitejs/plugin-vue'

const here = dirname(fileURLToPath(import.meta.url))
const root = resolve(here, '..')

const appSource = readFileSync(resolve(root, 'src/App.vue'), 'utf8')
const navIds = [...appSource.matchAll(/id: '([^']+)'/g)].map((m) => m[1])

const COMPONENTS = [
  ['hash-', '/src/components/HashTool.vue'],
  ['cipher-', '/src/components/SymmetricCipher.vue'],
  ['encode-', '/src/components/EncodeDecode.vue'],
  ['kdf-', '/src/components/KdfTool.vue'],
  ['random-', '/src/components/RandomTool.vue'],
]
const ASYMMETRIC = ['rsa', 'ecdsa', 'ed25519', 'sm2']

function componentFor (id) {
  for (const [prefix, path] of COMPONENTS) if (id.startsWith(prefix)) return path
  if (ASYMMETRIC.includes(id)) return '/src/components/AsymmetricCipher.vue'
  return null
}

const server = await createServer({
  root,
  configFile: false,
  logLevel: 'error',
  appType: 'custom',
  server: { middlewareMode: true, hmr: false },
  // jsencrypt 的 lib/index.js 用了无扩展名相对导入（import './JSEncrypt'）。
  // 浏览器构建时会被打包器解析掉，但 SSR 默认把依赖外部化交给 Node 解析，就会找不到文件。
  // 只对 jsencrypt 取消外部化（它是纯 ESM，能安全打包）；
  // crypto-js / sm-crypto 是 CJS/UMD，取消外部化后会被当 ESM 执行而报错，必须保持外部化。
  ssr: { noExternal: ['jsencrypt'] },
  plugins: [vue()],
})

let pass = 0
const failures = []

try {
  for (const id of navIds) {
    const path = componentFor(id)
    if (!path) {
      failures.push(`${id}: 找不到对应组件`)
      continue
    }
    try {
      const mod = await server.ssrLoadModule(path)
      const app = createSSRApp(mod.default, { tool: id })
      app.config.warnHandler = () => {}
      const html = await renderToString(app)
      if (!html || html.length < 100) throw new Error(`渲染结果过短（${html.length} 字节）`)
      if (/NaN|undefined\b(?![^<]*<\/)/.test(html.replace(/<[^>]*>/g, ' '))) {
        // 仅提示型检查：页面上不该出现字面量 NaN
        if (/\bNaN\b/.test(html)) throw new Error('渲染结果里出现了 NaN')
      }
      pass++
      if (!process.env.QUIET) console.log(`  ok   ${id.padEnd(20)} ${html.length} 字节`)
    } catch (e) {
      failures.push(`${id}: ${e.message}`)
      console.log(`  FAIL ${id.padEnd(20)} ${e.message}`)
    }
  }
} finally {
  await server.close()
}

console.log('\n' + '='.repeat(46))
console.log(`渲染通过 ${pass} / 失败 ${failures.length}`)
if (failures.length) {
  console.log('\n失败明细：')
  for (const f of failures) console.log('  - ' + f)
  process.exitCode = 1
}
