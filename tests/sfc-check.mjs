/**
 * 静态检查所有 .vue 单文件组件：
 *   1. 能否正常编译（模板语法、<script setup> 语法）
 *   2. 模板里引用的标识符是否都能在 <script setup> 中找到 —— 找不到的会编译成 `_ctx.xxx`，
 *      在运行时表现为「点了没反应 / 显示空白」，这类问题 Vite 构建是不会报错的。
 *
 * 运行： node --import ./tests/register.mjs tests/sfc-check.mjs
 */
import { readFileSync, readdirSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parse, compileScript, compileTemplate } from '@vue/compiler-sfc'

const here = dirname(fileURLToPath(import.meta.url))
const srcDir = resolve(here, '..', 'src')

let pass = 0
const failures = []

function ok (name) {
  pass++
  if (!process.env.QUIET) console.log(`  ok   ${name}`)
}
function bad (name, detail) {
  failures.push(`${name}${detail ? ' -> ' + detail : ''}`)
  console.log(`  FAIL ${name}${detail ? ' -> ' + detail : ''}`)
}

const files = [
  join(srcDir, 'App.vue'),
  ...readdirSync(join(srcDir, 'components')).map((f) => join(srcDir, 'components', f)),
].filter((f) => f.endsWith('.vue'))

/* 模板里允许出现的运行时全局对象 / 编译器内部标识符 */
const WHITELIST = new Set([
  '$slots', '$props', '$attrs', '$emit', '$el', '$refs', '$options', '$forceUpdate',
  '$nextTick', '$watch', '$data', '$root', '$parent', '$children', '$createElement',
  '$set', '$delete', '$on', '$once', '$off', '_createElementVNode', '_createTextVNode',
])

console.log('\n== 单文件组件静态检查 ==')

for (const file of files) {
  const label = file.slice(srcDir.length + 1).replace(/\\/g, '/')
  const source = readFileSync(file, 'utf8')

  const { descriptor, errors } = parse(source, { filename: file })
  if (errors.length) {
    bad(`${label} 解析`, errors.map((e) => e.message).join('; '))
    continue
  }

  let script
  try {
    script = compileScript(descriptor, { id: label })
  } catch (e) {
    bad(`${label} <script setup> 编译`, e.message)
    continue
  }

  const bindings = new Set(Object.keys(script.bindings || {}))

  if (descriptor.template) {
    let tmpl
    try {
      tmpl = compileTemplate({
        id: label,
        filename: file,
        source: descriptor.template.content,
        compilerOptions: { bindingMetadata: script.bindings, prefixIdentifiers: true },
      })
    } catch (e) {
      bad(`${label} 模板编译`, e.message)
      continue
    }
    if (tmpl.errors && tmpl.errors.length) {
      bad(
        `${label} 模板编译`,
        tmpl.errors.map((e) => (typeof e === 'string' ? e : e.message)).join('; ')
      )
      continue
    }

    // 未在 <script setup> 中声明的引用会以 _ctx.xxx 形式出现在生成的渲染函数里
    const missing = new Set()
    const re = /_ctx\.([A-Za-z_$][\w$]*)/g
    let m
    while ((m = re.exec(tmpl.code))) {
      if (!WHITELIST.has(m[1])) missing.add(m[1])
    }
    if (missing.size) {
      bad(`${label} 模板引用了未定义的标识符`, [...missing].join(', '))
      continue
    }
  }

  ok(`${label}（绑定 ${bindings.size} 个）`)
}

/* ---------------- 导航项与组件路由一致性 ---------------- */

console.log('\n== 导航 / 路由一致性 ==')
const appSource = readFileSync(join(srcDir, 'App.vue'), 'utf8')
const navIds = [...appSource.matchAll(/id: '([^']+)'/g)].map((m) => m[1])
const unique = new Set(navIds)
if (navIds.length !== unique.size) {
  bad('导航 id 唯一', `重复：${navIds.filter((v, i) => navIds.indexOf(v) !== i).join(', ')}`)
} else {
  ok(`${navIds.length} 个导航 id 均唯一`)
}

const seen = new Set()
for (const id of navIds) {
  const prefixOk =
    id.startsWith('hash-') ||
    id.startsWith('cipher-') ||
    id.startsWith('encode-') ||
    id.startsWith('kdf-') ||
    id.startsWith('random-') ||
    ['rsa', 'ecdsa', 'ed25519', 'sm2'].includes(id)
  if (!prefixOk) bad(`导航 id 能被路由匹配：${id}`, '没有任何 v-if 分支会命中它')
  else seen.add(id)
}
if (seen.size === navIds.length) ok(`${navIds.length} 个导航 id 全部能匹配到组件分支`)

/* 每个组件的取模表是否覆盖了对应的所有导航 id */
const tableChecks = [
  ['src/utils/hash.js', 'HASH_ALGORITHMS', (id) => id.startsWith('hash-')],
  ['src/utils/cipher.js', 'SYMMETRIC_ALGOS', (id) => id.startsWith('cipher-')],
  ['src/utils/encode.js', 'ENCODE_TOOLS', (id) => id.startsWith('encode-')],
  ['src/utils/kdf.js', 'KDF_TOOLS', (id) => id.startsWith('kdf-')],
  ['src/utils/random.js', 'RANDOM_TOOLS', (id) => id.startsWith('random-')],
]

const mods = {
  'src/utils/hash.js': await import('../src/utils/hash.js'),
  'src/utils/cipher.js': await import('../src/utils/cipher.js'),
  'src/utils/encode.js': await import('../src/utils/encode.js'),
  'src/utils/kdf.js': await import('../src/utils/kdf.js'),
  'src/utils/random.js': await import('../src/utils/random.js'),
}

for (const [modPath, exportName, match] of tableChecks) {
  const mod = mods[modPath]
  const table = mod[exportName]
  const expected = navIds.filter(match)
  const actual = Array.isArray(table) ? table.map((t) => t.id) : Object.keys(table)
  const missing = expected.filter((id) => !actual.includes(id))
  const extra = actual.filter((id) => !navIds.includes(id))
  if (missing.length) bad(`${modPath} 的 ${exportName} 缺少`, missing.join(', '))
  else if (extra.length) bad(`${modPath} 的 ${exportName} 多出`, extra.join(', '))
  else ok(`${exportName} 覆盖全部 ${expected.length} 个导航 id`)
}

console.log('\n' + '='.repeat(46))
console.log(`通过 ${pass} / 失败 ${failures.length}`)
if (failures.length) {
  console.log('\n失败明细：')
  for (const f of failures) console.log('  - ' + f)
  process.exitCode = 1
}
