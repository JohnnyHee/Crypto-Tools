<script setup>
import { computed, onMounted, reactive, ref, watch } from 'vue'
import {
  EC_CURVES,
  EC_HASHES,
  EC_SIGNATURE_FORMATS,
  ed25519Available,
  ed25519Sign,
  ed25519Verify,
  ecdsaSign,
  ecdsaVerify,
  generateEcKeyPair,
  generateEd25519KeyPair,
  generateRsaKeyPair,
  generateSm2KeyPair,
  rsaDecrypt,
  rsaEncrypt,
  rsaMaxPlaintext,
  rsaSign,
  rsaVerify,
  sm2Decrypt,
  sm2Encrypt,
  sm2Sign,
  sm2Verify,
  webCryptoAvailable,
} from '../utils/asymmetric.js'
import { copyText } from '../utils/clipboard.js'

const props = defineProps({
  tool: { type: String, default: 'rsa' },
})

/* 每个算法各自保存一份密钥，切换左侧菜单时不会把已生成的密钥冲掉 */
const keyStore = reactive({
  rsa: { publicKey: '', privateKey: '' },
  ecdsa: { publicKey: '', privateKey: '' },
  ed25519: { publicKey: '', privateKey: '' },
  sm2: { publicKey: '', privateKey: '' },
})

const TOOL_DEFS = {
  rsa: {
    label: 'RSA',
    operations: ['keygen', 'encrypt', 'decrypt', 'sign', 'verify'],
    note: '公钥加密 / 私钥解密，私钥签名 / 公钥验签',
  },
  ecdsa: {
    label: 'ECDSA',
    operations: ['keygen', 'sign', 'verify'],
    note: '椭圆曲线签名算法，只能签名与验签，不能加密',
  },
  ed25519: {
    label: 'Ed25519',
    operations: ['keygen', 'sign', 'verify'],
    note: 'Edwards 曲线签名，签名固定 64 字节',
  },
  sm2: {
    label: 'SM2',
    operations: ['keygen', 'encrypt', 'decrypt', 'sign', 'verify'],
    note: '国密椭圆曲线公钥算法（GB/T 32918）',
  },
}

const OP_LABELS = {
  keygen: '生成密钥对',
  encrypt: '公钥加密',
  decrypt: '私钥解密',
  sign: '私钥签名',
  verify: '公钥验签',
}
const OP_PLACEHOLDER = {
  encrypt: '输入要加密的明文…',
  decrypt: '粘贴要解密的密文（Base64 / Hex）…',
  sign: '输入要签名的内容…',
  verify: '输入被签名的原始内容…',
}

const currentTool = computed(() => (TOOL_DEFS[props.tool] ? props.tool : 'rsa'))
const def = computed(() => TOOL_DEFS[currentTool.value])
const keys = computed(() => keyStore[currentTool.value])

const activeOp = ref('keygen')
const inputText = ref('Hello, 加解密工具集!')
const signature = ref('')
const result = ref('')
const error = ref('')
const notice = ref('')
const loading = ref(false)
const verifyPassed = ref(null)
const copied = ref('')
const edSupported = ref(true)

/* RSA 参数 */
const rsaBits = ref(2048)
const rsaPadding = ref('pkcs1')
const rsaDigest = ref('sha256')
/* ECDSA 参数 */
const ecCurve = ref('P-256')
const ecHash = ref('SHA-256')
const ecFormat = ref('der')
/* SM2 参数 */
const sm2Mode = ref(1)
const sm2Der = ref(true)

/**
 * 修复点：旧版 `toolType` 是个内部 ref（默认 'rsa'），完全没读 props.tool，
 * 所以点侧边栏的 ECDSA / SM2 永远只显示 RSA；而且切换算法时 `activeOp`
 * 不重置，切到 ECDSA 后仍停在 'encrypt'，执行时 switch 没有匹配分支，
 * 界面静默什么都不发生。
 */
watch(
  () => props.tool,
  () => {
    activeOp.value = def.value.operations[0]
    result.value = ''
    error.value = ''
    notice.value = ''
    verifyPassed.value = null
    signature.value = ''
  },
  { immediate: true }
)

const keyHint = computed(() => {
  const t = currentTool.value
  if (t === 'sm2') return 'SM2 公钥 130 位 Hex（04‖X‖Y），私钥 64 位 Hex'
  if (t === 'ecdsa') return `ECDSA ${ecCurve.value} 公私钥为 PEM（SPKI / PKCS#8）`
  if (t === 'ed25519') return 'Ed25519 公私钥为 PEM（SPKI / PKCS#8）'
  return 'PKCS#8 私钥 / SPKI 公钥 PEM，也接受 PKCS#1 与裸 Base64'
})

const maxPlaintext = computed(() => {
  if (currentTool.value !== 'rsa' || !keys.value.publicKey) return null
  try {
    return rsaMaxPlaintext(keys.value.publicKey, rsaPadding.value)
  } catch (e) {
    return null
  }
})

const needsSignature = computed(() => activeOp.value === 'verify' && currentTool.value !== 'rsa')
const isVerify = computed(() => activeOp.value === 'verify')

onMounted(async () => {
  edSupported.value = await ed25519Available()
})

function reset() {
  result.value = ''
  error.value = ''
  notice.value = ''
  verifyPassed.value = null
}

async function copy(label, text) {
  const ok = await copyText(text)
  if (ok) {
    copied.value = label
    setTimeout(() => (copied.value = ''), 1200)
  }
}

async function generateKeys() {
  reset()
  loading.value = true
  try {
    if (currentTool.value === 'rsa') {
      const pair = await generateRsaKeyPair(rsaBits.value)
      keys.value.publicKey = pair.publicKey
      keys.value.privateKey = pair.privateKey
      notice.value = `已生成 RSA-${pair.bits} 密钥对${webCryptoAvailable() ? '（WebCrypto / crypto.subtle 生成）' : '（jsencrypt 生成）'}`
    } else if (currentTool.value === 'ecdsa') {
      const pair = await generateEcKeyPair(ecCurve.value)
      keys.value.publicKey = pair.publicKey
      keys.value.privateKey = pair.privateKey
      notice.value = `已生成 ${ecCurve.value}（secp${ecCurve.value.replace('P-', '') === '521' ? '521r1' : ecCurve.value.replace('P-', '') + 'r1'}）密钥对`
    } else if (currentTool.value === 'ed25519') {
      if (!edSupported.value) throw new Error('当前浏览器不支持 Ed25519（需要 Chrome 113+ / Firefox 130+）')
      const pair = await generateEd25519KeyPair()
      keys.value.publicKey = pair.publicKey
      keys.value.privateKey = pair.privateKey
      notice.value = '已生成 Ed25519 密钥对'
    } else {
      const pair = generateSm2KeyPair()
      keys.value.publicKey = pair.publicKey
      keys.value.privateKey = pair.privateKey
      notice.value = '已生成 SM2 密钥对'
    }
  } catch (e) {
    error.value = e.message || String(e)
  } finally {
    loading.value = false
  }
}

async function run() {
  reset()
  if (activeOp.value === 'keygen') return generateKeys()
  if (activeOp.value === 'verify' && !keys.value.publicKey) {
    error.value = '请先填写或生成公钥'
    return
  }
  if (activeOp.value !== 'verify' && !keys.value.publicKey && !keys.value.privateKey) {
    error.value = '请先填写或生成密钥'
    return
  }
  loading.value = true
  const t = currentTool.value
  try {
    if (activeOp.value === 'encrypt') {
      if (!keys.value.publicKey) throw new Error('加密需要公钥')
      result.value = t === 'sm2'
        ? sm2Encrypt(inputText.value, keys.value.publicKey, Number(sm2Mode.value))
        : await rsaEncrypt(inputText.value, keys.value.publicKey, rsaPadding.value)
    } else if (activeOp.value === 'decrypt') {
      if (!keys.value.privateKey) throw new Error('解密需要私钥')
      result.value = t === 'sm2'
        ? sm2Decrypt(inputText.value, keys.value.privateKey, Number(sm2Mode.value))
        : await rsaDecrypt(inputText.value, keys.value.privateKey, rsaPadding.value)
    } else if (activeOp.value === 'sign') {
      if (!keys.value.privateKey) throw new Error('签名需要私钥')
      if (t === 'rsa') result.value = rsaSign(inputText.value, keys.value.privateKey, rsaDigest.value)
      else if (t === 'ecdsa') {
        result.value = await ecdsaSign({
          text: inputText.value,
          privateKey: keys.value.privateKey,
          curve: ecCurve.value,
          hash: ecHash.value,
          format: ecFormat.value,
        })
      } else if (t === 'ed25519') {
        result.value = await ed25519Sign(inputText.value, keys.value.privateKey)
      } else {
        result.value = sm2Sign(inputText.value, keys.value.privateKey, { der: sm2Der.value })
      }
      signature.value = result.value
    } else if (activeOp.value === 'verify') {
      const sig = signature.value || result.value
      if (!sig) throw new Error('请先在"私钥签名"里生成签名，或把签名粘到签名框')
      if (t === 'rsa') {
        verifyPassed.value = rsaVerify(inputText.value, sig, keys.value.publicKey, rsaDigest.value)
      } else if (t === 'ecdsa') {
        verifyPassed.value = await ecdsaVerify({
          text: inputText.value,
          signature: sig,
          publicKey: keys.value.publicKey,
          curve: ecCurve.value,
          hash: ecHash.value,
          format: ecFormat.value,
        })
      } else if (t === 'ed25519') {
        verifyPassed.value = await ed25519Verify(inputText.value, sig, keys.value.publicKey)
      } else {
        verifyPassed.value = sm2Verify(inputText.value, sig, keys.value.publicKey, { der: sm2Der.value })
      }
      result.value = verifyPassed.value ? '签名有效 ✓ 内容与公钥匹配' : '签名无效 ✗ 内容被改动，或密钥 / 参数不匹配'
    }
  } catch (e) {
    verifyPassed.value = activeOp.value === 'verify' ? false : null
    error.value = e.message || String(e)
  } finally {
    loading.value = false
  }
}

function clearKeys() {
  keys.value.publicKey = ''
  keys.value.privateKey = ''
  reset()
}
</script>

<template>
  <div class="tool-page">
    <div class="tool-header">
      <h2>{{ def.label }} <span class="badge">{{ def.note }}</span></h2>
      <p>{{ keyHint }}</p>
    </div>

    <div class="tabs">
      <button
        v-for="op in def.operations"
        :key="op"
        class="tab"
        :class="{ active: activeOp === op }"
        :disabled="op === 'keygen' && loading"
        @click="activeOp = op; reset()"
      >
        {{ OP_LABELS[op] }}
      </button>
    </div>

    <div v-if="currentTool === 'ed25519' && !edSupported" class="alert alert-warn">
      当前浏览器不支持 Ed25519（<code>crypto.subtle</code> 里没有 Ed25519）。请使用较新的 Chrome / Edge / Firefox，
      并通过 https 或 localhost 打开本页面。
    </div>

    <!-- 密钥 -->
    <div class="card">
      <div class="card-title">
        <span>密钥</span>
        <button class="btn btn-sm" @click="copy('公钥', keys.publicKey)" :disabled="!keys.publicKey">
          {{ copied === '公钥' ? '已复制 ✓' : '复制公钥' }}
        </button>
        <button class="btn btn-sm" @click="copy('私钥', keys.privateKey)" :disabled="!keys.privateKey">
          {{ copied === '私钥' ? '已复制 ✓' : '复制私钥' }}
        </button>
        <button class="btn btn-sm" @click="clearKeys" :disabled="!keys.publicKey && !keys.privateKey">清空</button>
      </div>

      <div class="field">
        <label class="field-label">公钥</label>
        <textarea v-model="keys.publicKey" spellcheck="false" rows="4" :placeholder="currentTool === 'sm2' ? '04 开头的 130 位 Hex 公钥' : '-----BEGIN PUBLIC KEY-----'" />
      </div>
      <div class="field">
        <label class="field-label">私钥</label>
        <textarea v-model="keys.privateKey" spellcheck="false" rows="4" :placeholder="currentTool === 'sm2' ? '64 位 Hex 私钥' : '-----BEGIN PRIVATE KEY-----'" />
      </div>
    </div>

    <!-- 参数 -->
    <div class="card" v-if="currentTool === 'rsa' || currentTool === 'ecdsa' || currentTool === 'sm2'">
      <div class="card-title">参数</div>
      <div class="form-grid">
        <template v-if="currentTool === 'rsa'">
          <div class="field">
            <label class="field-label">密钥长度</label>
            <select v-model="rsaBits" :disabled="activeOp !== 'keygen'">
              <option :value="512">512 位（仅演示，不安全）</option>
              <option :value="1024">1024 位</option>
              <option :value="2048">2048 位（推荐）</option>
              <option :value="4096">4096 位（较慢）</option>
            </select>
          </div>
          <div class="field">
            <label class="field-label">填充方式</label>
            <select v-model="rsaPadding" :disabled="!['encrypt', 'decrypt'].includes(activeOp)">
              <option value="pkcs1">PKCS#1 v1.5（jsencrypt 默认）</option>
              <option value="oaep">RSA-OAEP / SHA-256（WebCrypto）</option>
            </select>
            <div class="field-hint" v-if="maxPlaintext !== null">当前公钥单次最多加密 {{ maxPlaintext }} 字节</div>
          </div>
          <div class="field">
            <label class="field-label">签名摘要</label>
            <select v-model="rsaDigest" :disabled="!['sign', 'verify'].includes(activeOp)">
              <option value="sha256">SHA-256</option>
              <option value="sha1">SHA-1</option>
              <option value="sha512">SHA-512</option>
            </select>
          </div>
        </template>

        <template v-if="currentTool === 'ecdsa'">
          <div class="field">
            <label class="field-label">曲线</label>
            <select v-model="ecCurve" :disabled="activeOp !== 'keygen'">
              <option v-for="c in EC_CURVES" :key="c.id" :value="c.id">{{ c.label }}</option>
            </select>
          </div>
          <div class="field">
            <label class="field-label">哈希</label>
            <select v-model="ecHash">
              <option v-for="h in EC_HASHES" :key="h.id" :value="h.id">{{ h.label }}</option>
            </select>
          </div>
          <div class="field">
            <label class="field-label">签名格式</label>
            <select v-model="ecFormat" :disabled="!['sign', 'verify'].includes(activeOp)">
              <option v-for="f in EC_SIGNATURE_FORMATS" :key="f.id" :value="f.id">{{ f.label }}</option>
            </select>
            <div class="field-hint">DER 是 OpenSSL / Java 通用格式；RAW 是 r‖s 直连。</div>
          </div>
        </template>

        <template v-if="currentTool === 'sm2'">
          <div class="field">
            <label class="field-label">密文顺序</label>
            <select v-model="sm2Mode" :disabled="!['encrypt', 'decrypt'].includes(activeOp)">
              <option :value="1">C1C3C2（新标准 GB/T 32918.4）</option>
              <option :value="0">C1C2C3（旧标准，兼容部分老系统）</option>
            </select>
          </div>
          <div class="field">
            <label class="field-label">签名编码</label>
            <select v-model="sm2Der" :disabled="!['sign', 'verify'].includes(activeOp)">
              <option :value="true">DER（ASN.1）</option>
              <option :value="false">RAW（r‖s，128 位 Hex）</option>
            </select>
          </div>
        </template>
      </div>
    </div>

    <!-- 输入 / 结果 -->
    <div class="card">
      <div class="card-title">
        <span>{{ activeOp === 'keygen' ? '操作' : OP_LABELS[activeOp] }}</span>
        <span class="spacer" />
        <button class="btn btn-sm" :disabled="!result" @click="copy('结果', result)">
          {{ copied === '结果' ? '已复制 ✓' : '复制结果' }}
        </button>
      </div>

      <template v-if="activeOp === 'keygen'">
        <p class="stat">点击下方按钮生成一对新密钥，会覆盖当前密钥框的内容。</p>
        <div class="actions" style="margin-top: 12px">
          <button class="btn btn-primary" :disabled="loading" @click="generateKeys">
            {{ loading ? '生成中…' : `生成 ${def.label} 密钥对` }}
          </button>
        </div>
      </template>

      <template v-else>
        <div class="field">
          <label class="field-label">{{ OP_PLACEHOLDER[activeOp] || '输入内容' }}</label>
          <textarea v-model="inputText" spellcheck="false" />
        </div>
        <div v-if="needsSignature || activeOp === 'verify'" class="field">
          <label class="field-label">签名（Hex 或 Base64）</label>
          <textarea v-model="signature" spellcheck="false" rows="3" placeholder="在此粘贴签名；刚用私钥签过名的话会自动填入" />
        </div>
        <div class="actions">
          <button class="btn btn-primary" :disabled="loading" @click="run">
            {{ loading ? '计算中…' : OP_LABELS[activeOp] }}
          </button>
        </div>
      </template>
    </div>

    <div class="card" v-if="result || error || notice">
      <div class="card-title">
        <span>输出</span>
        <span v-if="isVerify && verifyPassed !== null" class="badge" :style="{ color: verifyPassed ? 'var(--success)' : 'var(--danger)' }">
          {{ verifyPassed ? 'VERIFIED' : 'FAILED' }}
        </span>
      </div>
      <div v-if="result" class="output-box">{{ result }}</div>
      <div v-if="error" class="alert alert-error">{{ error }}</div>
      <div v-if="notice" class="alert alert-success">{{ notice }}</div>
    </div>

    <div class="alert alert-info">
      <template v-if="currentTool === 'rsa'">
        RSA 密钥优先用 WebCrypto 生成（位数精确），PKCS#1 v1.5 走的仍是 jsencrypt。
        加密内容不能超过密钥长度减去填充开销；加密长文本请先对称加密，再用 RSA 加密那把对称密钥。
      </template>
      <template v-else-if="currentTool === 'ecdsa'">
        ECDSA 签名每次都会随机化，所以对同一内容连续签名两次结果不同——这是正常现象，两次都能验签通过。
      </template>
      <template v-else-if="currentTool === 'ed25519'">
        Ed25519 签名固定 64 字节（Base64 后 88 个字符），比 ECDSA 更快也更难误用。
      </template>
      <template v-else>
        SM2 公钥为 <code>04‖X‖Y</code> 共 130 位 Hex（也接受 128 位 X‖Y），密文默认按 C1C3C2 排列。
        签名默认 DER 编码——底层 sm-crypto 返回的就是 Hex 字符串，旧版把它当作字节数组又转了一次十六进制，
        导致签名永远验不过。
      </template>
    </div>
  </div>
</template>
