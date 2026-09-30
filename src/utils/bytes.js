/**
 * 字节 / 编码工具集
 *
 * 统一以 Uint8Array 作为二进制载体，只在调用 crypto-js 时转换成 WordArray，
 * 避免各个组件各自做一遍字符串转换（旧版本大量依赖 CryptoJS.enc.* 的
 * 隐式转换，导致口令式加密、IV 失效等问题）。
 */
import CryptoJS from 'crypto-js'

const encoder = typeof TextEncoder !== 'undefined' ? new TextEncoder() : null
const decoder = typeof TextDecoder !== 'undefined' ? new TextDecoder('utf-8', { fatal: true }) : null

/* ---------------------------------------------------------- UTF-8 */

export function utf8ToBytes(str) {
  if (encoder) return encoder.encode(String(str))
  return CryptoJS.enc.Utf8.parse(String(str))
}

export function bytesToUtf8(bytes) {
  try {
    if (decoder) return decoder.decode(bytes)
    return CryptoJS.enc.Utf8.stringify(bytesToWordArray(bytes))
  } catch (e) {
    throw new Error('数据不是合法的 UTF-8 文本（可能密钥/IV 不正确，或原文为二进制）')
  }
}

/* ---------------------------------------------------------- Hex */

export function bytesToHex(bytes) {
  let out = ''
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0')
  return out
}

export function hexToBytes(hex) {
  const s = String(hex).trim().replace(/^0x/i, '').replace(/[\s:]/g, '')
  if (s.length === 0) return new Uint8Array(0)
  if (s.length % 2 !== 0) throw new Error(`Hex 字符串长度必须为偶数（当前 ${s.length} 个字符）`)
  if (!/^[0-9a-fA-F]+$/.test(s)) throw new Error('Hex 字符串包含非法字符（只允许 0-9 a-f）')
  const out = new Uint8Array(s.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16)
  return out
}

/* ---------------------------------------------------------- Base64 */

export function bytesToBase64(bytes, { urlSafe = false, pad = true } = {}) {
  let binary = ''
  const CHUNK = 0x8000
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK))
  }
  const b64 = typeof btoa === 'function' ? btoa(binary) : Buffer.from(bytes).toString('base64')
  let out = b64
  if (urlSafe) out = out.replace(/\+/g, '-').replace(/\//g, '_')
  if (!pad) out = out.replace(/=+$/, '')
  return out
}

export function base64ToBytes(input) {
  let s = String(input).replace(/\s+/g, '')
  if (s.length === 0) return new Uint8Array(0)
  s = s.replace(/-/g, '+').replace(/_/g, '/')
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s)) {
    throw new Error('不是合法的 Base64 字符串（包含非法字符）')
  }
  const rem = s.length % 4
  if (rem === 1) throw new Error('Base64 字符串长度非法')
  if (rem) s += '='.repeat(4 - rem)
  let binary
  try {
    binary = atob(s)
  } catch (e) {
    throw new Error('不是合法的 Base64 字符串（解码失败）')
  }
  const out = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i)
  return out
}

/** 严格的 Base64 校验：非法字符 / 长度错误都会抛错（crypto-js 会静默产出 \0） */
export function isBase64(input) {
  const s = String(input).replace(/\s+/g, '')
  if (s.length === 0) return false
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(s) && !/^[A-Za-z0-9\-_]+={0,2}$/.test(s)) return false
  return s.length % 4 !== 1
}

/* ---------------------------------------------------------- WordArray 互转 */

export function bytesToWordArray(bytes) {
  const words = []
  for (let i = 0; i < bytes.length; i++) {
    const idx = i >>> 2
    words[idx] = (words[idx] || 0) | (bytes[i] << (24 - (i % 4) * 8))
  }
  return CryptoJS.lib.WordArray.create(words, bytes.length)
}

export function wordArrayToBytes(wa) {
  const out = new Uint8Array(wa.sigBytes)
  for (let i = 0; i < wa.sigBytes; i++) {
    out[i] = (wa.words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff
  }
  return out
}

/* ---------------------------------------------------------- 其它编码 */

export function bytesToBase64Url(bytes, pad = false) {
  return bytesToBase64(bytes, { urlSafe: true, pad })
}

export function base64UrlToBytes(str) {
  return base64ToBytes(String(str).replace(/-/g, '+').replace(/_/g, '/'))
}

/* ---------------------------------------------------------- 随机数 */

export function randomBytes(n) {
  const out = new Uint8Array(n)
  if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.getRandomValues) {
    globalThis.crypto.getRandomValues(out)
    return out
  }
  throw new Error('当前环境不支持安全随机数（crypto.getRandomValues 不可用）')
}

export function randomHex(n) {
  return bytesToHex(randomBytes(n))
}

/* ---------------------------------------------------------- PEM */

export function bytesToPem(label, bytes, lineLength = 64) {
  const b64 = bytesToBase64(bytes)
  const lines = b64.match(new RegExp(`.{1,${lineLength}}`, 'g')) || []
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----`
}

export function pemToBytes(pem) {
  const text = String(pem).trim()
  if (!text) throw new Error('PEM 内容为空')
  const match = /-----BEGIN [^-]+-----([\s\S]*?)-----END [^-]+-----/.exec(text)
  const body = (match ? match[1] : text).replace(/\s+/g, '')
  if (!body) throw new Error('PEM 内容为空或格式不正确')
  return base64ToBytes(body)
}

export function pemLabel(pem) {
  const m = /-----BEGIN ([^-]+)-----/.exec(String(pem))
  return m ? m[1].trim() : ''
}

/**
 * 把各种写法的密钥统一成规范的 PEM：
 * PKCS#1 -> PKCS#8、PKCS#1 公钥 -> SPKI、裸 Base64 / 缺头尾 / 多余空白都能吃进来。
 */
export function normalizePem(pem) {
  const label = pemLabel(pem)
  const der = pemToBytes(pem)
  if (/RSA PRIVATE KEY/.test(label)) return bytesToPem('PRIVATE KEY', pkcs1ToPkcs8(der))
  if (/RSA PUBLIC KEY/.test(label)) return bytesToPem('PUBLIC KEY', pkcs1PublicToSpki(der))
  if (/PRIVATE KEY/.test(label) || /PUBLIC KEY/.test(label)) return bytesToPem(label, der)
  if (label) return bytesToPem(label, der)
  const priv = sniffPrivateKey(der)
  if (priv === 'pkcs1') return bytesToPem('PRIVATE KEY', pkcs1ToPkcs8(der))
  if (priv === 'pkcs8') return bytesToPem('PRIVATE KEY', der)
  const pub = sniffPublicKey(der)
  if (pub === 'pkcs1') return bytesToPem('PUBLIC KEY', pkcs1PublicToSpki(der))
  if (pub === 'spki') return bytesToPem('PUBLIC KEY', der)
  return bytesToPem('PRIVATE KEY', der)
}

/**
 * 没有 PEM 头时靠 DER 结构猜私钥格式。
 * PKCS#8 = SEQUENCE { INTEGER 0, SEQUENCE{alg}, OCTET STRING }
 * PKCS#1 = SEQUENCE { INTEGER 0, INTEGER n, ... }
 */
export function sniffPrivateKey(der) {
  try {
    const outer = readTlv(der, 0)
    if (outer.tag !== 0x30) return 'unknown'
    const first = readTlv(outer.content, 0)
    if (first.tag !== 0x02) return 'unknown'
    const second = readTlv(outer.content, first.total)
    if (second.tag === 0x30) return 'pkcs8'
    if (second.tag === 0x02) return 'pkcs1'
  } catch (e) { /* 结构不认识 */ }
  return 'unknown'
}

/** SPKI = SEQUENCE { SEQUENCE{alg}, BIT STRING }；PKCS#1 公钥 = SEQUENCE { INTEGER n, INTEGER e } */
export function sniffPublicKey(der) {
  try {
    const outer = readTlv(der, 0)
    if (outer.tag !== 0x30) return 'unknown'
    const first = readTlv(outer.content, 0)
    if (first.tag === 0x30) return 'spki'
    if (first.tag === 0x02) return 'pkcs1'
  } catch (e) { /* 结构不认识 */ }
  return 'unknown'
}

/* ---------------------------------------------------------- DER / PKCS#1 <-> PKCS#8 */

const RSA_ALGORITHM_IDENTIFIER = hexToBytes('300d06092a864886f70d0101010500')

function derLengthBytes (n) {
  if (n < 0x80) return new Uint8Array([n])
  const parts = []
  let v = n
  while (v > 0) {
    parts.unshift(v & 0xff)
    v = Math.floor(v / 256)
  }
  return new Uint8Array([0x80 | parts.length, ...parts])
}

function derTlv (tag, content) {
  return concatBytes(new Uint8Array([tag]), derLengthBytes(content.length), content)
}

function readDerLength (bytes, offset) {
  const first = bytes[offset]
  if (first === undefined) throw new Error('DER 数据不完整')
  if (first < 0x80) return { length: first, bytes: 1 }
  const n = first & 0x7f
  let length = 0
  for (let i = 0; i < n; i++) length = length * 256 + bytes[offset + 1 + i]
  return { length, bytes: 1 + n }
}

function readTlv (bytes, offset) {
  const tag = bytes[offset]
  const { length, bytes: lenSize } = readDerLength(bytes, offset + 1)
  const start = offset + 1 + lenSize
  return { tag, content: bytes.subarray(start, start + length), total: 1 + lenSize + length }
}

/** PKCS#1 RSAPrivateKey -> PKCS#8 PrivateKeyInfo */
export function pkcs1ToPkcs8 (pkcs1) {
  const version = new Uint8Array([0x02, 0x01, 0x00])
  return derTlv(0x30, concatBytes(version, RSA_ALGORITHM_IDENTIFIER, derTlv(0x04, pkcs1)))
}

/** PKCS#8 PrivateKeyInfo -> PKCS#1 RSAPrivateKey */
export function pkcs8ToPkcs1 (pkcs8) {
  const outer = readTlv(pkcs8, 0)
  if (outer.tag !== 0x30) throw new Error('PKCS#8 数据格式不正确')
  const c = outer.content
  let off = 0
  const ver = readTlv(c, off)
  if (ver.tag !== 0x02) throw new Error('PKCS#8 缺少 version 字段')
  off += ver.total
  const alg = readTlv(c, off)
  off += alg.total
  const octet = readTlv(c, off)
  if (octet.tag !== 0x04) throw new Error('PKCS#8 中未找到私钥数据')
  return octet.content
}

/** PKCS#1 RSAPublicKey -> SPKI SubjectPublicKeyInfo */
export function pkcs1PublicToSpki (pkcs1) {
  const bitString = derTlv(0x03, concatBytes(new Uint8Array([0x00]), pkcs1))
  return derTlv(0x30, concatBytes(RSA_ALGORITHM_IDENTIFIER, bitString))
}

/** SPKI SubjectPublicKeyInfo -> PKCS#1 RSAPublicKey */
export function spkiToPkcs1 (spki) {
  const outer = readTlv(spki, 0)
  if (outer.tag !== 0x30) throw new Error('SPKI 数据格式不正确')
  const c = outer.content
  let off = 0
  const alg = readTlv(c, off)
  off += alg.total
  const bit = readTlv(c, off)
  if (bit.tag !== 0x03) throw new Error('SPKI 中未找到公钥数据')
  return bit.content.subarray(1)
}

/* ---------------------------------------------------------- 比较 / 拼接 */

export function bytesEqual(a, b) {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}

export function concatBytes(...arrays) {
  const total = arrays.reduce((n, a) => n + a.length, 0)
  const out = new Uint8Array(total)
  let offset = 0
  for (const a of arrays) {
    out.set(a, offset)
    offset += a.length
  }
  return out
}

/* ---------------------------------------------------------- ECDSA 签名格式（RAW <-> DER） */

function derEncodeInt(bytes) {
  let i = 0
  while (i < bytes.length - 1 && bytes[i] === 0) i++
  let body = bytes.subarray(i)
  if (body.length === 0) body = new Uint8Array([0])
  if (body[0] & 0x80) body = concatBytes(new Uint8Array([0]), body)
  return concatBytes(new Uint8Array([0x02, body.length]), body)
}

/** WebCrypto 的 r||s 原始签名 -> DER 编码 */
export function rawSignatureToDer(raw) {
  if (raw.length % 2 !== 0) throw new Error('ECDSA 原始签名长度必须为偶数')
  const half = raw.length / 2
  const r = derEncodeInt(raw.subarray(0, half))
  const s = derEncodeInt(raw.subarray(half))
  const len = r.length + s.length
  if (len < 128) return concatBytes(new Uint8Array([0x30, len]), r, s)
  return concatBytes(new Uint8Array([0x30, 0x81, len]), r, s)
}

/** DER 编码签名 -> r||s 原始签名 */
export function derSignatureToRaw(der, size = 0) {
  let i = 0
  if (der[i++] !== 0x30) throw new Error('不是合法的 DER 签名（缺少 SEQUENCE 头）')
  let len = der[i++]
  if (len & 0x80) {
    const n = len & 0x7f
    len = 0
    for (let k = 0; k < n; k++) len = (len << 8) | der[i++]
  }
  if (der[i++] !== 0x02) throw new Error('不是合法的 DER 签名（缺少 INTEGER）')
  let rLen = der[i++]
  const r = der.subarray(i, i + rLen)
  i += rLen
  if (der[i++] !== 0x02) throw new Error('不是合法的 DER 签名（缺少 INTEGER）')
  let sLen = der[i++]
  const s = der.subarray(i, i + sLen)
  const strip = (b) => {
    let k = 0
    while (k < b.length - 1 && b[k] === 0) k++
    return b.subarray(k)
  }
  const rOut = strip(r)
  const sOut = strip(s)
  const n = size ? Math.floor(size) : Math.max(rOut.length, sOut.length)
  const leftPad = (b) => {
    if (b.length > n) throw new Error('DER 签名的整数长度超出预期')
    const out = new Uint8Array(n)
    out.set(b, n - b.length)
    return out
  }
  return concatBytes(leftPad(rOut), leftPad(sOut))
}

export { CryptoJS }
