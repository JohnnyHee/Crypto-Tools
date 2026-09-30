<script setup>
import { computed, ref, watch } from 'vue'
import {
  KEY_FORMATS,
  SYMMETRIC_ALGOS,
  decryptSymmetric,
  deriveIvBytes,
  deriveKeyBytes,
  encryptSymmetric,
  fitKeyBytes,
  getAlgo,
  modesForAlgo,
  paddingsForAlgo,
  randomIvHex,
} from '../utils/cipher.js'
import { copyText } from '../utils/clipboard.js'
import { bytesToHex } from '../utils/bytes.js'

const props = defineProps({
  tool: { type: String, default: 'cipher-aes' },
})

const spec = computed(() => getAlgo(props.tool))

const mode = ref('encrypt') // encrypt | decrypt
const secretKey = ref('0123456789abcdef')
const keyFormat = ref('utf8')
const cipherMode = ref('CBC')
const padding = ref('Pkcs7')
const iv = ref('')
const ivFormat = ref('utf8')
const inputText = ref('Hello, World! 你好，世界！')
const outputEncoding = ref('base64')
const inputEncoding = ref('base64')
const result = ref('')
const resultMeta = ref('')
const error = ref('')
const copied = ref(false)

const modes = computed(() => modesForAlgo(props.tool))
const paddings = computed(() => paddingsForAlgo(props.tool))
const isStream = computed(() => !!spec.value.stream)
const needsIv = computed(
  () => !isStream.value ? !!spec.value.ivSize && cipherMode.value !== 'ECB' : !!spec.value.ivSize
)
const ivOptional = computed(() => !!spec.value.optionalIV)

// 切换算法：把模式/填充/密钥重置到该算法的合法取值
// （旧版没有这一步，选中 SM4 却留着 AES 的模式，点加密直接抛错）
watch(
  () => props.tool,
  () => {
    const s = spec.value
    secretKey.value = s.defaultKeyText
    const ms = modesForAlgo(props.tool)
    cipherMode.value = ms.length ? (ms.some((m) => m.id === 'CBC') ? 'CBC' : ms[0].id) : 'CBC'
    const ps = paddingsForAlgo(props.tool)
    padding.value = ps.length ? 'Pkcs7' : 'NoPadding'
    iv.value = ''
    result.value = ''
    resultMeta.value = ''
    error.value = ''
    copied.value = false
  },
  { immediate: true }
)

// 切到 ECB 时清掉 IV，避免把不用的 IV 传给底层
watch(cipherMode, (v) => {
  if (v === 'ECB') iv.value = ''
})

const keyInfo = computed(() => {
  try {
    const bytes = fitKeyBytes(props.tool, deriveKeyBytes(secretKey.value, keyFormat.value), keyFormat.value)
    return `${bytes.length} 字节（${bytes.length * 8} 位）`
  } catch (e) {
    return e.message
  }
})

const ivInfo = computed(() => {
  if (!needsIv.value) return ''
  try {
    return `${deriveIvBytes(props.tool, iv.value, ivFormat.value, cipherMode.value).length} 字节`
  } catch (e) {
    return e.message
  }
})

function makeRandomIv() {
  iv.value = randomIvHex(props.tool)
  ivFormat.value = 'hex'
}

function convert() {
  result.value = ''
  resultMeta.value = ''
  error.value = ''
  copied.value = false
  try {
    const keyBytes = fitKeyBytes(props.tool, deriveKeyBytes(secretKey.value, keyFormat.value), keyFormat.value)
    const ivBytes = needsIv.value
      ? deriveIvBytes(props.tool, iv.value, ivFormat.value, cipherMode.value)
      : new Uint8Array(0)

    if (mode.value === 'encrypt') {
      result.value = encryptSymmetric({
        algoId: props.tool,
        keyBytes,
        ivBytes,
        mode: cipherMode.value,
        padding: padding.value,
        plaintext: inputText.value,
        outputEncoding: outputEncoding.value,
      })
      resultMeta.value = `${outputEncoding.value === 'hex' ? 'Hex' : 'Base64'} 输出 · ${result.value.replace(/\s/g, '').length / (outputEncoding.value === 'hex' ? 2 : 4) * (outputEncoding.value === 'hex' ? 1 : 3)} 字节左右`
    } else {
      const out = decryptSymmetric({
        algoId: props.tool,
        keyBytes,
        ivBytes,
        mode: cipherMode.value,
        padding: padding.value,
        ciphertext: inputText.value,
        inputEncoding: inputEncoding.value,
      })
      if (out.text) {
        result.value = out.text
      } else {
        result.value = `(解密成功，但结果不是合法的 UTF-8 文本)\nHex: ${bytesToHex(out.bytes)}`
      }
      resultMeta.value = `明文 ${out.bytes.length} 字节`
    }
  } catch (e) {
    error.value = e.message || String(e)
  }
}

watch([mode, secretKey, keyFormat, cipherMode, padding, iv, ivFormat, inputText, outputEncoding, inputEncoding, () => props.tool], convert, { immediate: true })

function swap() {
  if (mode.value === 'encrypt') {
    if (!result.value || error.value) return
    inputText.value = result.value
    inputEncoding.value = outputEncoding.value
    mode.value = 'decrypt'
  } else {
    if (!result.value) return
    inputText.value = result.value
    outputEncoding.value = inputEncoding.value === 'hex' ? 'hex' : 'base64'
    mode.value = 'encrypt'
  }
}

const opensslHint = computed(() => {
  const map = { 'cipher-aes': 'aes-128-cbc', 'cipher-des': 'des-cbc', 'cipher-tripledes': 'des3' }
  const base = map[props.tool]
  if (!base || isStream.value) return ''
  if (cipherMode.value === 'CBC') return `openssl enc -${base} -K <密钥hex> -iv <IV hex>`
  if (cipherMode.value === 'ECB') return `openssl enc -${base.replace('-cbc', '-ecb')} -K <密钥hex>`
  return `openssl enc -${base.replace('-cbc', '-' + cipherMode.value.toLowerCase())} -K <密钥hex> -iv <IV hex>`
})

async function doCopy() {
  const ok = await copyText(result.value)
  copied.value = ok
  if (ok) setTimeout(() => (copied.value = false), 1200)
}
</script>

<template>
  <div class="tool-page">
    <div class="tool-header">
      <h2>{{ spec.label }} <span class="badge">{{ isStream ? '流密码' : '分组密码' }}</span></h2>
      <p>{{ isStream ? '流密码逐字节运算，不使用分组模式与填充' : `分组大小 ${spec.blockSize} 字节 · 密钥 ${spec.keyHint}` }}</p>
    </div>

    <div class="tabs">
      <button class="tab" :class="{ active: mode === 'encrypt' }" @click="mode = 'encrypt'">加密</button>
      <button class="tab" :class="{ active: mode === 'decrypt' }" @click="mode = 'decrypt'">解密</button>
      <button class="tab" @click="swap" :title="mode === 'encrypt' ? '把密文填回输入框并切到解密' : '把明文填回输入框并切到加密'">
        ⇅ 结果回填
      </button>
    </div>

    <div class="card">
      <div class="card-title">
        <span>算法参数</span>
        <span class="badge">{{ spec.label }}</span>
      </div>

      <div class="form-grid">
        <div class="field">
          <label class="field-label">密钥（{{ keyFormat }}）</label>
          <input v-model="secretKey" type="text" spellcheck="false" :placeholder="spec.keyHint" />
          <div class="field-hint">{{ keyInfo }}</div>
        </div>

        <div class="field">
          <label class="field-label">密钥格式</label>
          <select v-model="keyFormat">
            <option v-for="f in KEY_FORMATS" :key="f.id" :value="f.id" :title="f.desc">{{ f.label }}</option>
          </select>
          <div class="field-hint">UTF-8 / Hex / Base64 按字面取字节；派生格式会先做摘要再截断到合法长度。</div>
        </div>

        <div v-if="!isStream" class="field">
          <label class="field-label">工作模式</label>
          <select v-model="cipherMode">
            <option v-for="m in modes" :key="m.id" :value="m.id" :title="m.desc">{{ m.label }}</option>
          </select>
          <div class="field-hint">{{ (modes.find((m) => m.id === cipherMode) || {}).desc }}</div>
        </div>

        <div v-if="!isStream" class="field">
          <label class="field-label">填充方式</label>
          <select v-model="padding">
            <option v-for="p in paddings" :key="p.id" :value="p.id" :title="p.desc">{{ p.label }}</option>
          </select>
          <div class="field-hint">{{ (paddings.find((p) => p.id === padding) || {}).desc }}</div>
        </div>
      </div>

      <div v-if="needsIv" class="form-grid" style="margin-top: 14px">
        <div class="field">
          <label class="field-label">IV 初始向量{{ ivOptional ? '（可选）' : '' }}</label>
          <input v-model="iv" type="text" spellcheck="false" :placeholder="`需要 ${spec.ivSize} 字节`" />
          <div class="field-hint">{{ ivInfo }}</div>
        </div>
        <div class="field">
          <label class="field-label">IV 格式</label>
          <select v-model="ivFormat">
            <option value="utf8">UTF-8 文本</option>
            <option value="hex">Hex（十六进制）</option>
            <option value="base64">Base64</option>
          </select>
        </div>
        <div class="field">
          <label class="field-label">&nbsp;</label>
          <button class="btn btn-block" @click="makeRandomIv">生成随机 IV</button>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="field">
        <label class="field-label">{{ mode === 'encrypt' ? '明文' : '密文' }}</label>
        <textarea v-model="inputText" spellcheck="false" />
      </div>
      <div class="form-grid">
        <div v-if="mode === 'encrypt'" class="field">
          <label class="field-label">密文输出编码</label>
          <select v-model="outputEncoding">
            <option value="base64">Base64</option>
            <option value="hex">Hex（十六进制）</option>
          </select>
        </div>
        <div v-else class="field">
          <label class="field-label">密文输入编码</label>
          <select v-model="inputEncoding">
            <option value="base64">Base64</option>
            <option value="hex">Hex（十六进制）</option>
          </select>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-title">
        <span>{{ mode === 'encrypt' ? '密文' : '明文' }}</span>
        <span class="stat">{{ resultMeta }}</span>
        <span class="spacer" />
        <button class="btn btn-sm" :disabled="!result" @click="doCopy">{{ copied ? '已复制 ✓' : '复制结果' }}</button>
      </div>
      <div v-if="result" class="output-box">{{ result }}</div>
      <div v-else class="output-box placeholder">（暂无结果）</div>
      <div v-if="error" class="alert alert-error">{{ error }}</div>
    </div>

    <div class="alert alert-info">
      本工具直接使用密钥字节（不是 OpenSSL 的口令派生），所以 IV 完全可控，密文也不带 <code>Salted__</code> 前缀。
      <template v-if="opensslHint"><br />与 OpenSSL 互通：<code>{{ opensslHint }}</code>。</template>
    </div>
  </div>
</template>
