<script setup>
import { computed, ref, watch } from 'vue'
import { ENCODE_TOOLS, decodeText, encodeText, getEncodeTool, precheckDecode } from '../utils/encode.js'
import { copyText } from '../utils/clipboard.js'

const props = defineProps({
  tool: { type: String, default: 'encode-base64' },
})

const spec = computed(() => getEncodeTool(props.tool))
const isDecodeOnly = computed(() => !!spec.value.decodeOnly)

const mode = ref('encode')
const inputText = ref('Hello, World! 你好，世界！')
const output = ref('')
const error = ref('')
const copied = ref('')

/* 选项 */
const lineBreak = ref(false)
const upper = ref(false)
const component = ref(true)

const options = computed(() => ({
  lineBreak: lineBreak.value,
  upper: upper.value,
  component: component.value,
}))

/**
 * 修复点：旧版用 `watch([mode, inputText, () => props.tool], performOperation)`，
 * 但解码失败时 catch 里只设 error、不输出结果，且结尾有段
 * `if (!output.value && output.value !== '')` 的死代码永远不会执行。
 * 这里改成纯函数式换算，并区分「输入为空」和「输入非法」。
 */
function compute() {
  error.value = ''
  output.value = ''
  if (spec.value.decodeOnly) mode.value = 'decode'
  if (mode.value === 'encode' && !spec.value.encode) {
    error.value = `${spec.value.label} 只支持解析，不支持编码`
    return
  }
  if (inputText.value === '') {
    output.value = ''
    return
  }
  try {
    if (mode.value === 'decode') {
      const pre = precheckDecode(props.tool, inputText.value)
      if (pre) throw new Error(pre)
      output.value = decodeText(props.tool, inputText.value)
    } else {
      output.value = encodeText(props.tool, inputText.value, options.value)
    }
    if (output.value === '') output.value = ''
  } catch (e) {
    error.value = e.message || String(e)
  }
}

watch([mode, inputText, () => props.tool, options], compute, { immediate: true, deep: true })

watch(
  () => props.tool,
  () => {
    const s = getEncodeTool(props.tool)
    inputText.value = s.placeholder
    mode.value = s.decodeOnly ? 'decode' : 'encode'
    copied.value = ''
  }
)

async function copyResult() {
  if (await copyText(output.value)) {
    copied.value = '已复制 ✓'
    setTimeout(() => (copied.value = ''), 1200)
  }
}

function swap() {
  const next = output.value
  output.value = ''
  inputText.value = next
  if (!spec.value.decodeOnly) mode.value = mode.value === 'encode' ? 'decode' : 'encode'
}

const inputBytes = computed(() => new TextEncoder().encode(inputText.value).length)
const outputBytes = computed(() => new TextEncoder().encode(output.value).length)
</script>

<template>
  <div class="tool-page">
    <div class="tool-header">
      <h2>{{ spec.label }}</h2>
      <p>{{ spec.desc }}</p>
    </div>

    <div class="tabs">
      <button class="tab" :class="{ active: mode === 'encode' }" :disabled="isDecodeOnly" @click="mode = 'encode'">
        编码 Encode
      </button>
      <button class="tab" :class="{ active: mode === 'decode' }" @click="mode = 'decode'">
        {{ isDecodeOnly ? '解析 Decode' : '解码 Decode' }}
      </button>
    </div>

    <div class="card" v-if="!isDecodeOnly && (tool === 'encode-base64' || tool === 'encode-hex' || tool === 'encode-url')">
      <div class="card-title">选项</div>
      <label class="checkbox-row" v-if="tool === 'encode-base64'">
        <input type="checkbox" v-model="lineBreak" />
        <span>每 76 字符换行（MIME / PEM 风格）</span>
      </label>
      <label class="checkbox-row" v-if="tool === 'encode-hex'">
        <input type="checkbox" v-model="upper" />
        <span>使用大写字母（A-F）</span>
      </label>
      <label class="checkbox-row" v-if="tool === 'encode-url'">
        <input type="checkbox" v-model="component" />
        <span>使用 encodeURIComponent（连 <code>/ : ? &amp;</code> 也一起转义）</span>
      </label>
    </div>

    <div class="card">
      <div class="card-title">
        <span>{{ mode === 'decode' ? '输入（待解码）' : '输入（待编码）' }}</span>
        <span class="stat">{{ inputText.length }} 字符 · {{ inputBytes }} 字节</span>
      </div>
      <textarea
        v-model="inputText"
        spellcheck="false"
        :placeholder="mode === 'decode' ? spec.decodePlaceholder : spec.placeholder"
      />
      <div class="actions">
        <button class="btn btn-sm" @click="swap" :disabled="!output">⇅ 结果回填</button>
        <button class="btn btn-sm" @click="inputText = ''">清空</button>
      </div>
    </div>

    <div class="card">
      <div class="card-title">
        <span>{{ mode === 'decode' ? '解码结果' : '编码结果' }}</span>
        <span class="stat" v-if="output">{{ output.length }} 字符 · {{ outputBytes }} 字节</span>
        <button class="btn btn-sm" :disabled="!output" @click="copyResult">{{ copied || '复制' }}</button>
      </div>
      <div v-if="error" class="alert alert-error">{{ error }}</div>
      <div v-else-if="!output" class="output-box placeholder">结果会实时显示在这里…</div>
      <div v-else class="output-box mono-block" :style="tool === 'encode-jwt' ? 'white-space: pre-wrap' : ''">{{ output }}</div>
    </div>

    <div class="alert alert-info" v-if="tool === 'encode-jwt'">
      解析 JWT 只会解开 Base64URL 的头部和载荷——<strong>它不验证签名</strong>，任何人拿到 token 都能看到这些内容，
      所以千万别把敏感信息塞进 payload。
    </div>
    <div class="alert alert-info" v-else-if="tool === 'encode-unicode'">
      反向解析支持 <code>\uXXXX</code>、<code>\u{1F600}</code> 和 <code>\xNN</code> 三种写法，
      emoji 会被拆成一对代理项（surrogate pair）。
    </div>
    <div class="alert alert-info" v-else>
      所有编解码都在浏览器本地完成，输入内容不会发送到任何服务器。
    </div>
  </div>
</template>
