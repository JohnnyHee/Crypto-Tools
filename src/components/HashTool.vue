<script setup>
import { computed, ref, watch } from 'vue'
import {
  HASH_ALGORITHMS,
  availableHmacAlgorithms,
  computeHash,
  computeHmac,
} from '../utils/hash.js'
import { bytesToBase64, hexToBytes, utf8ToBytes } from '../utils/bytes.js'
import { copyText } from '../utils/clipboard.js'

const props = defineProps({
  tool: { type: String, default: 'hash-md5' },
})

const spec = computed(() => HASH_ALGORITHMS[props.tool] || HASH_ALGORITHMS['hash-md5'])

const mode = ref('hash') // hash | hmac
const inputText = ref('Hello, World!')
const hmacKey = ref('my-secret-key')
const keyFormat = ref('utf8')
const outFormat = ref('hex') // hex | hex-upper | base64
const copied = ref(false)

const hmacAlgorithms = availableHmacAlgorithms()
const hmacAlgo = ref('sha256')

// 切换左侧算法时，HMAC 算法要跟着切换（旧版在这里漏了重置，导致切换后仍用上一个算法）
watch(
  () => props.tool,
  () => {
    const id = spec.value.algo
    hmacAlgo.value = hmacAlgorithms.some((a) => a.id === id) ? id : 'sha256'
    copied.value = false
  },
  { immediate: true }
)

const outcome = computed(() => {
  try {
    const hex =
      mode.value === 'hmac'
        ? computeHmac(hmacAlgo.value, inputText.value, hmacKey.value, keyFormat.value)
        : computeHash(spec.value.algo, inputText.value)
    return { hex, error: '' }
  } catch (e) {
    return { hex: '', error: e.message || String(e) }
  }
})

const display = computed(() => {
  const hex = outcome.value.hex
  if (!hex) return ''
  if (outFormat.value === 'hex-upper') return hex.toUpperCase()
  if (outFormat.value === 'base64') return bytesToBase64(hexToBytes(hex))
  return hex
})

const inputBytes = computed(() => utf8ToBytes(inputText.value).length)
const outputBits = computed(() => (outcome.value.hex ? outcome.value.hex.length / 2 * 8 : 0))

const insecure = computed(() => ['md5', 'sha1', 'crc32'].includes(spec.value.algo))

async function doCopy() {
  const ok = await copyText(display.value)
  copied.value = ok
  if (ok) setTimeout(() => (copied.value = false), 1200)
}
</script>

<template>
  <div class="tool-page">
    <div class="tool-header">
      <h2>
        {{ spec.label }}
        <span v-if="mode === 'hmac'" class="badge">HMAC</span>
      </h2>
      <p>{{ spec.note || '输入任意文本，实时计算摘要值（结果为十六进制）' }}</p>
    </div>

    <div class="tabs">
      <button class="tab" :class="{ active: mode === 'hash' }" @click="mode = 'hash'">摘要</button>
      <button class="tab" :class="{ active: mode === 'hmac' }" @click="mode = 'hmac'">HMAC 消息认证码</button>
    </div>

    <div class="card">
      <div class="field">
        <label class="field-label">输入文本（UTF-8）</label>
        <textarea v-model="inputText" spellcheck="false" placeholder="在此输入或粘贴文本…" />
        <div class="field-hint">{{ inputText.length }} 字符 / {{ inputBytes }} 字节</div>
      </div>

      <template v-if="mode === 'hmac'">
        <div class="form-grid">
          <div class="field">
            <label class="field-label">密钥</label>
            <input v-model="hmacKey" type="text" spellcheck="false" placeholder="用于计算 HMAC 的密钥" />
          </div>
          <div class="field">
            <label class="field-label">密钥格式</label>
            <select v-model="keyFormat">
              <option value="utf8">UTF-8 文本</option>
              <option value="hex">Hex（十六进制）</option>
              <option value="base64">Base64</option>
            </select>
          </div>
          <div class="field">
            <label class="field-label">HMAC 算法</label>
            <select v-model="hmacAlgo">
              <option v-for="a in hmacAlgorithms" :key="a.id" :value="a.id">{{ a.label }}</option>
            </select>
          </div>
        </div>
      </template>

      <div class="field">
        <label class="field-label">输出格式</label>
        <div class="tabs">
          <button class="tab" :class="{ active: outFormat === 'hex' }" @click="outFormat = 'hex'">小写 Hex</button>
          <button class="tab" :class="{ active: outFormat === 'hex-upper' }" @click="outFormat = 'hex-upper'">大写 Hex</button>
          <button class="tab" :class="{ active: outFormat === 'base64' }" @click="outFormat = 'base64'">Base64</button>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-title">
        <span>{{ mode === 'hmac' ? 'HMAC 结果' : '摘要结果' }}</span>
        <span class="stat" v-if="outcome.hex">{{ outputBits }} bit</span>
        <span class="spacer" />
        <button class="btn btn-sm" :disabled="!display" @click="doCopy">
          {{ copied ? '已复制 ✓' : '复制结果' }}
        </button>
      </div>
      <div v-if="display" class="output-box">{{ display }}</div>
      <div v-else class="output-box placeholder">（暂无结果）</div>
      <div v-if="outcome.error" class="alert alert-error">{{ outcome.error }}</div>
    </div>

    <div v-if="insecure" class="alert alert-warn">
      <strong>{{ spec.label }}</strong> {{ spec.algo === 'crc32' ? '只是校验和，不具备抗碰撞能力' : '已被证明可构造碰撞，不应再用于安全场景' }}，
      建议改用 SHA-256 或 SM3。
    </div>
    <div v-if="mode === 'hmac' && hmacAlgo === 'sm3'" class="alert alert-info">
      HMAC-SM3 由 sm-crypto 的带密钥 SM3 实现（GB/T 32905-2016）。
    </div>
  </div>
</template>
