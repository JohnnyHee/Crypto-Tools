<script setup>
import { computed, reactive, ref, watch } from 'vue'
import {
  PASSWORD_SETS,
  RANDOM_OUTPUT_FORMATS,
  formatRandomBytes,
  generatePassword,
  nanoid,
  shortId,
  ulid,
  uuidV4,
  uuidV7,
} from '../utils/random.js'
import { randomBytes } from '../utils/bytes.js'
import { copyText } from '../utils/clipboard.js'

const props = defineProps({
  tool: { type: String, default: 'random-bytes' },
})

/* ------------------------------------------------ 随机字节 */
const byteCount = ref(32)
const byteFormat = ref('hex')
const bytesResult = ref('')

function makeBytes() {
  const n = Math.max(1, Math.min(1024, Math.floor(Number(byteCount.value)) || 1))
  byteCount.value = n
  bytesResult.value = formatRandomBytes(randomBytes(n), byteFormat.value)
}

/* ------------------------------------------------ 随机密码 */
const opts = reactive({
  length: 20,
  lower: true,
  upper: true,
  digits: true,
  symbols: true,
  avoidAmbiguous: true,
  requireEach: true,
})
const passwordCount = ref(5)
const passwords = ref([])
const passwordMeta = ref([])
const passwordError = ref('')

function makePasswords() {
  passwordError.value = ''
  try {
    const list = []
    let meta = []
    const n = Math.max(1, Math.min(20, Math.floor(Number(passwordCount.value)) || 1))
    passwordCount.value = n
    for (let i = 0; i < n; i++) {
      const { password, meta: m } = generatePassword({ ...opts })
      list.push(password)
      meta = m
    }
    passwords.value = list
    passwordMeta.value = meta
  } catch (e) {
    passwordError.value = e.message || String(e)
    passwords.value = []
  }
}

/* ------------------------------------------------ 唯一 ID */
const idKind = ref('uuid-v4')
const idCount = ref(5)
const nanoidSize = ref(21)
const shortBytes = ref(12)
const shortUpper = ref(false)
const ids = ref([])

const ID_KINDS = [
  { id: 'uuid-v4', label: 'UUID v4（随机）' },
  { id: 'uuid-v7', label: 'UUID v7（时间有序）' },
  { id: 'ulid', label: 'ULID（时间有序、可排序）' },
  { id: 'nanoid', label: 'NanoID（短、URL 安全）' },
  { id: 'short', label: '短 ID（自定义字节数）' },
]

function makeIds() {
  const n = Math.max(1, Math.min(50, Math.floor(Number(idCount.value)) || 1))
  idCount.value = n
  const list = []
  for (let i = 0; i < n; i++) {
    switch (idKind.value) {
      case 'uuid-v7':
        list.push(uuidV7())
        break
      case 'ulid':
        list.push(ulid())
        break
      case 'nanoid':
        list.push(nanoid(Math.max(4, Math.min(64, Number(nanoidSize.value) || 21))))
        break
      case 'short':
        list.push(shortId(Math.max(4, Math.min(64, Number(shortBytes.value) || 12)), shortUpper.value))
        break
      default:
        list.push(uuidV4())
    }
  }
  ids.value = list
}

/* 切换工具时清掉旧结果，避免把随机字节当成 UUID 复制走 */
watch(
  () => props.tool,
  () => {
    bytesResult.value = ''
    passwords.value = []
    passwordMeta.value = []
    passwordError.value = ''
    ids.value = []
  }
)

const currentResult = computed(() => {
  if (props.tool === 'random-bytes') return bytesResult.value
  if (props.tool === 'random-password') return passwords.value.join('\n')
  return ids.value.join('\n')
})

const copied = ref('')
async function copyResult() {
  if (await copyText(currentResult.value)) {
    copied.value = '已复制 ✓'
    setTimeout(() => (copied.value = ''), 1200)
  }
}

const entropyBits = computed(() => {
  const pools = []
  if (opts.lower) pools.push(PASSWORD_SETS.lower)
  if (opts.upper) pools.push(PASSWORD_SETS.upper)
  if (opts.digits) pools.push(PASSWORD_SETS.digits)
  if (opts.symbols) pools.push(PASSWORD_SETS.symbols)
  const all = pools.join('')
  const pool = opts.avoidAmbiguous ? all.replace(/[Il1O0o]/g, '') : all
  if (!pool.length) return 0
  return Math.round(opts.length * Math.log2(pool.length) * 10) / 10
})
</script>

<template>
  <div class="tool-page">
    <div class="tool-header">
      <h2>
        {{ tool === 'random-bytes' ? '随机字节' : tool === 'random-password' ? '随机密码' : 'UUID / 唯一 ID' }}
        <span class="badge">CSPRNG</span>
      </h2>
      <p>
        全部通过 <code>crypto.getRandomValues</code> 生成（密码洗牌用的是 32 位拒绝采样，没有模偏差），
        不用 <code>Math.random()</code>。
      </p>
    </div>

    <!-- 随机字节 -->
    <div class="card" v-if="tool === 'random-bytes'">
      <div class="card-title">参数</div>
      <div class="form-grid">
        <div class="field">
          <label class="field-label">字节数</label>
          <input type="number" v-model.number="byteCount" min="1" max="1024" />
          <div class="field-hint">1 – 1024 字节</div>
        </div>
        <div class="field">
          <label class="field-label">输出格式</label>
          <select v-model="byteFormat">
            <option v-for="f in RANDOM_OUTPUT_FORMATS" :key="f.id" :value="f.id">{{ f.label }}</option>
          </select>
        </div>
      </div>
      <div class="actions">
        <button class="btn btn-primary" @click="makeBytes">生成随机字节</button>
      </div>
    </div>

    <!-- 随机密码 -->
    <div class="card" v-if="tool === 'random-password'">
      <div class="card-title">参数</div>
      <div class="form-grid">
        <div class="field">
          <label class="field-label">密码长度（字符）</label>
          <input type="number" v-model.number="opts.length" min="4" max="512" />
        </div>
        <div class="field">
          <label class="field-label">生成数量</label>
          <input type="number" v-model.number="passwordCount" min="1" max="20" />
        </div>
      </div>
      <div class="checkbox-list">
        <label class="checkbox-row"><input type="checkbox" v-model="opts.lower" /><span>小写字母 a-z</span></label>
        <label class="checkbox-row"><input type="checkbox" v-model="opts.upper" /><span>大写字母 A-Z</span></label>
        <label class="checkbox-row"><input type="checkbox" v-model="opts.digits" /><span>数字 0-9</span></label>
        <label class="checkbox-row"><input type="checkbox" v-model="opts.symbols" /><span>特殊符号 !@#$…</span></label>
        <label class="checkbox-row"><input type="checkbox" v-model="opts.avoidAmbiguous" /><span>排除易混淆字符 I l 1 O 0 o</span></label>
        <label class="checkbox-row"><input type="checkbox" v-model="opts.requireEach" /><span>每类字符至少出现一次</span></label>
      </div>
      <div class="field-hint">按当前设置，信息熵约 {{ entropyBits }} bit</div>
      <div class="actions">
        <button class="btn btn-primary" @click="makePasswords">生成密码</button>
      </div>
      <div v-if="passwordError" class="alert alert-error" style="margin-top: 12px">{{ passwordError }}</div>
    </div>

    <!-- 唯一 ID -->
    <div class="card" v-if="tool === 'random-uuid'">
      <div class="card-title">参数</div>
      <div class="form-grid">
        <div class="field">
          <label class="field-label">类型</label>
          <select v-model="idKind">
            <option v-for="k in ID_KINDS" :key="k.id" :value="k.id">{{ k.label }}</option>
          </select>
        </div>
        <div class="field">
          <label class="field-label">生成数量</label>
          <input type="number" v-model.number="idCount" min="1" max="50" />
        </div>
        <div class="field" v-if="idKind === 'nanoid'">
          <label class="field-label">NanoID 长度</label>
          <input type="number" v-model.number="nanoidSize" min="4" max="64" />
        </div>
        <div class="field" v-if="idKind === 'short'">
          <label class="field-label">随机字节数</label>
          <input type="number" v-model.number="shortBytes" min="4" max="64" />
        </div>
      </div>
      <label class="checkbox-row" v-if="idKind === 'short'">
        <input type="checkbox" v-model="shortUpper" /><span>使用大写字母</span>
      </label>
      <div class="actions">
        <button class="btn btn-primary" @click="makeIds">生成 ID</button>
      </div>
    </div>

    <div class="card">
      <div class="card-title">
        <span>结果</span>
        <button class="btn btn-sm" :disabled="!currentResult" @click="copyResult">{{ copied || '复制' }}</button>
      </div>
      <div v-if="!currentResult" class="output-box placeholder">点上方按钮生成…</div>
      <template v-else>
        <div class="output-box mono-block" :style="tool === 'random-bytes' ? '' : 'white-space: pre-wrap'">{{ currentResult }}</div>
        <div v-if="passwordMeta.length" class="tag-row" style="margin-top: 12px">
          <span class="tag" v-for="(m, i) in passwordMeta" :key="i">{{ m }}</span>
        </div>
      </template>
    </div>

    <div class="alert alert-info">
      随机性来源是操作系统的 CSPRNG，同一时刻刷新两次结果不会重复。
      UUID v4 完全随机；UUID v7 与 ULID 把毫秒时间戳放在前面，所以按字符串排序就是按时间排序，做主键时对数据库索引更友好。
    </div>
  </div>
</template>
