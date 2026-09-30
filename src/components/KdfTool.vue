<script setup>
import { computed, ref, watch } from 'vue'
import {
  KDF_HASHES,
  KDF_OUTPUT_FORMATS,
  KDF_TOOLS,
  deriveKey,
  formatKdfOutput,
  getKdfTool,
  parseKdfInput,
} from '../utils/kdf.js'
import { hexToBytes } from '../utils/bytes.js'
import { copyText } from '../utils/clipboard.js'

const props = defineProps({
  tool: { type: String, default: 'kdf-pbkdf2' },
})

const spec = computed(() => getKdfTool(props.tool))

const password = ref('correct horse battery staple')
const salt = ref('4142434445464748')
const saltFormat = ref('hex')
const info = ref('crypto-tools')
const infoFormat = ref('utf8')
const iterations = ref(100000)
const length = ref(32)
const hash = ref('sha256')
const outFormat = ref('hex')

const result = ref(null)
const error = ref('')
const elapsed = ref(0)
const copied = ref('')

const output = computed(() => {
  if (!result.value) return ''
  return formatKdfOutput(result.value.bytes, outFormat.value)
})

watch(
  () => props.tool,
  () => {
    result.value = null
    error.value = ''
  }
)

const saltBytes = computed(() => {
  try {
    return parseKdfInput(salt.value, saltFormat.value)
  } catch (e) {
    return new Uint8Array()
  }
})

function randomSalt() {
  const bytes = new Uint8Array(16)
  crypto.getRandomValues(bytes)
  saltFormat.value = 'hex'
  salt.value = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

/**
 * 刻意不做「输入即计算」：PBKDF2 十万次迭代在本机要 1.2 秒左右，
 * 每敲一个字符就算一次会把页面卡死。
 */
function derive() {
  error.value = ''
  result.value = null
  const t0 = performance.now()
  try {
    const params = {
      password: password.value,
      saltBytes: saltBytes.value,
      ikmBytes: saltBytes.value,
      infoBytes: parseKdfInput(info.value, infoFormat.value),
      iterations: Number(iterations.value),
      length: Number(length.value),
      hash: hash.value,
    }
    if (props.tool === 'kdf-hkdf' && !info.value) params.infoBytes = new Uint8Array()
    result.value = deriveKey(props.tool, params)
  } catch (e) {
    error.value = e.message || String(e)
  } finally {
    elapsed.value = Math.round(performance.now() - t0)
  }
}

async function copyResult() {
  if (await copyText(output.value)) {
    copied.value = '已复制 ✓'
    setTimeout(() => (copied.value = ''), 1200)
  }
}
</script>

<template>
  <div class="tool-page">
    <div class="tool-header">
      <h2>{{ spec.label }} <span class="badge">密钥派生 KDF</span></h2>
      <p>{{ spec.desc }}</p>
    </div>

    <div class="card">
      <div class="card-title">参数</div>
      <div class="form-grid">
        <div class="field">
          <label class="field-label">{{ tool === 'kdf-hkdf' ? '输入密钥材料 IKM' : '口令 / 密码' }}</label>
          <textarea v-model="password" spellcheck="false" rows="2" placeholder="要派生的口令或密钥材料" />
        </div>
        <div class="field">
          <label class="field-label">盐 Salt {{ tool === 'kdf-hkdf' ? '（可选）' : '' }}</label>
          <textarea v-model="salt" spellcheck="false" rows="2" placeholder="每个用途使用不同的盐" />
          <select v-model="saltFormat" style="margin-top: 6px">
            <option value="utf8">按 UTF-8 文本解释</option>
            <option value="hex">按 Hex 解释</option>
            <option value="base64">按 Base64 解释</option>
          </select>
          <div class="field-hint">当前 {{ saltBytes.length }} 字节</div>
        </div>
        <div class="field">
          <label class="field-label">哈希算法</label>
          <select v-model="hash">
            <option v-for="h in KDF_HASHES" :key="h.id" :value="h.id">{{ h.label }}</option>
          </select>
        </div>
        <div class="field">
          <label class="field-label">输出长度（字节）</label>
          <input type="number" v-model.number="length" min="1" max="1024" />
          <div class="field-hint">1 – 1024 字节</div>
        </div>
        <div class="field" v-if="tool === 'kdf-pbkdf2'">
          <label class="field-label">迭代次数</label>
          <input type="number" v-model.number="iterations" min="1" max="2000000" step="1000" />
          <div class="field-hint">推荐 ≥ 100000；数字越大越慢也越难暴力破解</div>
        </div>
        <template v-if="tool === 'kdf-hkdf'">
          <div class="field">
            <label class="field-label">上下文信息 Info</label>
            <textarea v-model="info" spellcheck="false" rows="2" placeholder="例如用途名称：加密 / 签名" />
            <select v-model="infoFormat" style="margin-top: 6px">
              <option value="utf8">按 UTF-8 文本解释</option>
              <option value="hex">按 Hex 解释</option>
              <option value="base64">按 Base64 解释</option>
            </select>
          </div>
        </template>
      </div>

      <div class="actions">
        <button class="btn btn-primary" @click="derive">派生密钥</button>
        <button class="btn" v-if="tool !== 'kdf-hkdf'" @click="randomSalt">随机生成 16 字节盐</button>
      </div>
    </div>

    <div class="card">
      <div class="card-title">
        <span>{{ spec.outputLabel }}</span>
        <span class="stat" v-if="result">耗时 {{ elapsed }} ms</span>
        <button class="btn btn-sm" :disabled="!output" @click="copyResult">{{ copied || '复制' }}</button>
      </div>

      <div class="field">
        <label class="field-label">输出格式</label>
        <select v-model="outFormat" style="max-width: 220px">
          <option v-for="f in KDF_OUTPUT_FORMATS" :key="f.id" :value="f.id">{{ f.label }}</option>
        </select>
      </div>

      <div v-if="error" class="alert alert-error">{{ error }}</div>
      <div v-else-if="!output" class="output-box placeholder">
        点「派生密钥」开始计算（这里刻意不做输入即计算，PBKDF2 十万次迭代要 1 秒以上）。
      </div>
      <div v-else class="output-box mono-block">{{ output }}</div>

      <div v-if="result" class="tag-row" style="margin-top: 12px">
        <span class="tag" v-for="(m, i) in result.meta" :key="i">{{ m }}</span>
      </div>
    </div>

    <div class="alert alert-info" v-if="tool === 'kdf-pbkdf2'">
      PBKDF2 保证「相同口令 + 相同盐 + 相同迭代 → 相同密钥」，所以盐必须随密文一起保存。
      本项目里「对称加密」页的密钥格式选「PBKDF2 派生」用的就是同一套算法。
    </div>
    <div class="alert alert-info" v-else-if="tool === 'kdf-hkdf'">
      HKDF 分两步：Extract 用盐把任意长度的 IKM 压成固定长度的 PRK，Expand 再用 info 把 PRK 扩展成任意长度。
      同一个 IKM 配不同 info 就能派生出互不相关的多把密钥。
    </div>
    <div class="alert alert-warn" v-else>
      摘要计数器派生（digest(password ‖ salt ‖ counter)）强度远低于 PBKDF2 / HKDF，
      只建议用来理解原理，不要用于真实的口令存储或密钥管理。
    </div>
  </div>
</template>
