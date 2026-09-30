import {
  CryptoJS,
  bytesToHex,
  bytesToBase64,
  bytesToWordArray,
  wordArrayToBytes,
  utf8ToBytes,
  hexToBytes,
  base64ToBytes,
  isBase64,
} from './bytes.js'
import smCrypto from 'sm-crypto'

const { sm3 } = smCrypto

export const KDF_HASHES = [
  { id: 'md5', label: 'MD5', hmac: () => CryptoJS.HmacMD5, digest: (wa) => CryptoJS.MD5(wa), algo: CryptoJS.algo.MD5, size: 16 },
  { id: 'sha1', label: 'SHA-1', hmac: () => CryptoJS.HmacSHA1, digest: (wa) => CryptoJS.SHA1(wa), algo: CryptoJS.algo.SHA1, size: 20 },
  { id: 'sha256', label: 'SHA-256', hmac: () => CryptoJS.HmacSHA256, digest: (wa) => CryptoJS.SHA256(wa), algo: CryptoJS.algo.SHA256, size: 32 },
  { id: 'sha512', label: 'SHA-512', hmac: () => CryptoJS.HmacSHA512, digest: (wa) => CryptoJS.SHA512(wa), algo: CryptoJS.algo.SHA512, size: 64 },
]

export const KDF_TOOLS = [
  {
    id: 'kdf-pbkdf2',
    label: 'PBKDF2',
    desc: 'RFC 8018 基于口令的密钥派生，通过大量迭代提高暴力破解成本。相同口令 + 相同盐必然得到相同密钥。',
    outputLabel: '派生密钥',
  },
  {
    id: 'kdf-hkdf',
    label: 'HKDF',
    desc: 'RFC 5869 基于 HMAC 的密钥派生：先 Extract 浓缩熵，再 Expand 扩展到目标长度。适合从一个主密钥派生出多个子密钥。',
    outputLabel: '派生密钥',
  },
  {
    id: 'kdf-digest',
    label: '摘要派生',
    desc: '最简单的派生方式：反复对「口令 + 盐 + 计数器」做摘要并拼接。强度最低，仅用于理解原理。',
    outputLabel: '派生密钥',
  },
]

export function getKdfTool (id) {
  return KDF_TOOLS.find((t) => t.id === id) || KDF_TOOLS[0]
}

export const KDF_OUTPUT_FORMATS = [
  { id: 'hex', label: 'Hex' },
  { id: 'base64', label: 'Base64' },
  { id: 'utf8', label: 'UTF-8 文本' },
]

function hashSpec (id) {
  return KDF_HASHES.find((h) => h.id === id) || KDF_HASHES[2]
}

/** 把用户输入的盐/信息按格式转成字节 */
export function parseKdfInput (text, format) {
  switch (format) {
    case 'hex':
      return hexToBytes(text)
    case 'base64':
      return base64ToBytes(text)
    case 'utf8':
      return utf8ToBytes(text)
    default:
      return utf8ToBytes(text)
  }
}

export function formatKdfOutput (bytes, format) {
  if (format === 'base64') return bytesToBase64(bytes)
  if (format === 'utf8') return new TextDecoder('utf-8', { fatal: false }).decode(bytes)
  return bytesToHex(bytes)
}

/* ---------------------------------------------------------- PBKDF2 */

export function pbkdf2 ({ password, salt, iterations = 100000, length = 32, hash = 'sha256' }) {
  const spec = hashSpec(hash)
  const adjusted = Math.ceil(length / spec.size) * spec.size
  const wa = CryptoJS.PBKDF2(String(password), bytesToWordArray(salt), {
    keySize: adjusted / 4,
    iterations: Math.max(1, Math.floor(iterations) || 1),
    hasher: spec.algo,
  })
  return wordArrayToBytes(wa).subarray(0, length)
}

/* ---------------------------------------------------------- HKDF */

function hmacBytes (hash, keyBytes, dataBytes) {
  const fn = hashSpec(hash).hmac()
  return wordArrayToBytes(fn(bytesToWordArray(dataBytes), bytesToWordArray(keyBytes)))
}

export function hkdfExtract ({ hash = 'sha256', salt, ikm }) {
  const spec = hashSpec(hash)
  const realSalt = salt && salt.length ? salt : new Uint8Array(spec.size)
  return hmacBytes(hash, realSalt, ikm)
}

export function hkdfExpand ({ hash = 'sha256', prk, info, length = 32 }) {
  const out = new Uint8Array(0)
  let block = new Uint8Array(0)
  let counter = 1
  const chunks = []
  while (chunks.reduce((n, c) => n + c.length, 0) < length) {
    if (counter > 255) throw new Error('HKDF 输出长度超出上限（255 × 摘要长度）')
    const data = new Uint8Array(block.length + info.length + 1)
    data.set(block, 0)
    data.set(info, block.length)
    data[data.length - 1] = counter
    block = hmacBytes(hash, prk, data)
    chunks.push(block)
    counter++
  }
  const total = chunks.reduce((n, c) => n + c.length, 0)
  const merged = new Uint8Array(total)
  let off = 0
  for (const c of chunks) {
    merged.set(c, off)
    off += c.length
  }
  return merged.subarray(0, length)
}

export function hkdf ({ ikm, salt, info, length = 32, hash = 'sha256' }) {
  return hkdfExpand({ hash, prk: hkdfExtract({ hash, salt, ikm }), info, length })
}

/* ---------------------------------------------------------- 摘要派生 */

export function digestDerive ({ password, salt, length = 32, hash = 'sha256' }) {
  const spec = hashSpec(hash)
  const out = new Uint8Array(length)
  let filled = 0
  let counter = 0
  while (filled < length) {
    const chunk = new Uint8Array(utf8ToBytes(String(password)).length + salt.length + 4)
    chunk.set(utf8ToBytes(String(password)), 0)
    chunk.set(salt, utf8ToBytes(String(password)).length)
    const dv = new DataView(chunk.buffer)
    dv.setUint32(chunk.length - 4, counter, false)
    const digest = wordArrayToBytes(spec.digest(bytesToWordArray(chunk)))
    const take = Math.min(digest.length, length - filled)
    out.set(digest.subarray(0, take), filled)
    filled += take
    counter++
  }
  return out
}

/* ---------------------------------------------------------- 统一入口 */

/**
 * @returns {{ bytes: Uint8Array, hex: string, base64: string, text: string, meta: string[] }}
 */
export function deriveKey (toolId, params) {
  const meta = []
  let bytes
  const length = Math.max(1, Math.min(1024, Math.floor(params.length) || 32))

  switch (toolId) {
    case 'kdf-pbkdf2': {
      const iterations = Math.max(1, Math.floor(params.iterations) || 100000)
      if (iterations > 2000000) throw new Error('迭代次数过大（上限 2000000），浏览器会长时间无响应')
      bytes = pbkdf2({
        password: params.password,
        salt: params.saltBytes,
        iterations,
        length,
        hash: params.hash,
      })
      meta.push(`算法 PBKDF2-${hashSpec(params.hash).label}`)
      meta.push(`迭代 ${iterations} 次`)
      meta.push(`盐长度 ${params.saltBytes.length} 字节`)
      break
    }
    case 'kdf-hkdf': {
      const prk = hkdfExtract({ hash: params.hash, salt: params.saltBytes, ikm: params.ikmBytes })
      meta.push(`算法 HKDF-${hashSpec(params.hash).label}`)
      meta.push(`PRK（Extract 中间量） ${bytesToHex(prk)}`)
      meta.push(`info 长度 ${params.infoBytes.length} 字节`)
      bytes = hkdfExpand({ hash: params.hash, prk, info: params.infoBytes, length })
      break
    }
    case 'kdf-digest':
    default: {
      bytes = digestDerive({
        password: params.password,
        salt: params.saltBytes,
        length,
        hash: params.hash,
      })
      meta.push(`算法 ${hashSpec(params.hash).label} 计数器派生`)
      meta.push('警告：该方式无法抵御 GPU 暴力破解，请勿用于真实口令存储')
      break
    }
  }

  meta.push(`输出长度 ${bytes.length} 字节 / ${bytes.length * 8} 位`)
  return {
    bytes,
    hex: bytesToHex(bytes),
    base64: bytesToBase64(bytes),
    text: new TextDecoder('utf-8', { fatal: false }).decode(bytes),
    meta,
  }
}

export { sm3, isBase64 }
