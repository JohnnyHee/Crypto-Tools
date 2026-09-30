/**
 * 哈希 / 摘要 / HMAC / 校验和
 *
 * 注意：crypto-js 的 `CryptoJS.SHA3` 实现的是 **Keccak**（SHA-3 定稿前的版本），
 * 与 NIST FIPS 202 的 SHA3-256/512 结果不同（例如 SHA3-256("abc") 应为
 * 3a985da7…，而 CryptoJS.SHA3 给出 Keccak 的 4e03657a…）。旧版界面直接把它
 * 标成 "SHA3"，属于误导。
 *
 * 这里通过继承 CryptoJS.algo.SHA3、只把填充字节由 0x01 改成 NIST 规定的 0x06，
 * 复用 crypto-js 已经写好且较快的 Keccak-f[1600] 核心，从而得到真正的
 * SHA3-224/256/384/512（已用 FIPS 202 官方向量验证）。
 */
import CryptoJS from 'crypto-js'
import smCrypto from 'sm-crypto'
import { bytesToHex, hexToBytes, utf8ToBytes, base64ToBytes, bytesToWordArray } from './bytes.js'

const { sm3 } = smCrypto

/* ---------------------------------------------------------- NIST SHA-3 */

const SHA3FIPS = CryptoJS.algo.SHA3.extend({
  _doFinalize: function () {
    const data = this._data
    const dataWords = data.words
    const nBitsLeft = data.sigBytes * 8
    const blockSizeBits = this.blockSize * 32

    // 与 Keccak 唯一的差异：填充后缀用 0x06（Keccak 为 0x01）
    dataWords[nBitsLeft >>> 5] |= 0x06 << (24 - (nBitsLeft % 32))
    dataWords[((Math.ceil((nBitsLeft + 1) / blockSizeBits) * blockSizeBits) >>> 5) - 1] |= 0x80
    data.sigBytes = dataWords.length * 4

    this._process()

    const state = this._state
    const outputLengthBytes = this.cfg.outputLength / 8
    const outputLengthLanes = outputLengthBytes / 8

    const hashWords = []
    for (let i = 0; i < outputLengthLanes; i++) {
      let laneMsw = state[i].high
      let laneLsw = state[i].low
      laneMsw = (((laneMsw << 8) | (laneMsw >>> 24)) & 0x00ff00ff) | (((laneMsw << 24) | (laneMsw >>> 8)) & 0xff00ff00)
      laneLsw = (((laneLsw << 8) | (laneLsw >>> 24)) & 0x00ff00ff) | (((laneLsw << 24) | (laneLsw >>> 8)) & 0xff00ff00)
      hashWords.push(laneLsw, laneMsw)
    }

    return new CryptoJS.lib.WordArray.init(hashWords, outputLengthBytes)
  },
})

/** NIST FIPS 202 SHA-3 */
export function sha3 (message, outputLength = 256) {
  return SHA3FIPS.create({ outputLength }).finalize(message).toString()
}

/** Keccak（SHA-3 定稿前版本，以太坊的 Keccak-256 即此） */
export function keccak (message, outputLength = 256) {
  return CryptoJS.SHA3(message, { outputLength }).toString()
}

/* ---------------------------------------------------------- CRC32 */

let crc32Table = null

function getCrcTable () {
  if (crc32Table) return crc32Table
  const table = new Int32Array(256)
  for (let n = 0; n < 256; n++) {
    let c = n
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
    table[n] = c
  }
  crc32Table = table
  return table
}

/** IEEE 802.3 CRC-32，返回 8 位小写 hex */
export function crc32 (bytes) {
  const table = getCrcTable()
  let crc = -1
  for (let i = 0; i < bytes.length; i++) crc = (crc >>> 8) ^ table[(crc ^ bytes[i]) & 0xff]
  return ((crc ^ -1) >>> 0).toString(16).padStart(8, '0')
}

/* ---------------------------------------------------------- 算法表 */

export const HASH_ALGORITHMS = {
  'hash-md5': { algo: 'md5', label: 'MD5', bits: 128, note: '已不安全，仅用于校验' },
  'hash-sha1': { algo: 'sha1', label: 'SHA-1', bits: 160, note: '已不安全，仅用于兼容旧系统' },
  'hash-sha224': { algo: 'sha224', label: 'SHA-224', bits: 224 },
  'hash-sha256': { algo: 'sha256', label: 'SHA-256', bits: 256 },
  'hash-sha384': { algo: 'sha384', label: 'SHA-384', bits: 384 },
  'hash-sha512': { algo: 'sha512', label: 'SHA-512', bits: 512 },
  'hash-sha3-224': { algo: 'sha3-224', label: 'SHA3-224', bits: 224, note: 'NIST FIPS 202' },
  'hash-sha3-256': { algo: 'sha3-256', label: 'SHA3-256', bits: 256, note: 'NIST FIPS 202' },
  'hash-sha3-384': { algo: 'sha3-384', label: 'SHA3-384', bits: 384, note: 'NIST FIPS 202' },
  'hash-sha3-512': { algo: 'sha3-512', label: 'SHA3-512', bits: 512, note: 'NIST FIPS 202' },
  'hash-keccak256': { algo: 'keccak256', label: 'Keccak-256', bits: 256, note: '以太坊使用，非 NIST 标准' },
  'hash-ripemd160': { algo: 'ripemd160', label: 'RIPEMD-160', bits: 160 },
  'hash-sm3': { algo: 'sm3', label: 'SM3', bits: 256, note: '国密 GB/T 32905-2016' },
  'hash-crc32': { algo: 'crc32', label: 'CRC32', bits: 32, note: '校验和，不是密码学哈希' },
}

export const HMAC_ALGORITHMS = [
  { id: 'md5', label: 'HMAC-MD5' },
  { id: 'sha1', label: 'HMAC-SHA1' },
  { id: 'sha224', label: 'HMAC-SHA224' },
  { id: 'sha256', label: 'HMAC-SHA256' },
  { id: 'sha384', label: 'HMAC-SHA384' },
  { id: 'sha512', label: 'HMAC-SHA512' },
  { id: 'ripemd160', label: 'HMAC-RIPEMD160' },
  { id: 'sm3', label: 'HMAC-SM3' },
]

const HMAC_HELPERS = {
  md5: 'HmacMD5',
  sha1: 'HmacSHA1',
  sha224: 'HmacSHA224',
  sha256: 'HmacSHA256',
  sha384: 'HmacSHA384',
  sha512: 'HmacSHA512',
  ripemd160: 'HmacRIPEMD160',
}

/* ---------------------------------------------------------- 计算入口 */

/** @returns {string} 小写 hex */
export function computeHash (algo, text) {
  const msg = String(text ?? '')
  switch (algo) {
    case 'md5':
      return CryptoJS.MD5(msg).toString()
    case 'sha1':
      return CryptoJS.SHA1(msg).toString()
    case 'sha224':
      return CryptoJS.SHA224(msg).toString()
    case 'sha256':
      return CryptoJS.SHA256(msg).toString()
    case 'sha384':
      return CryptoJS.SHA384(msg).toString()
    case 'sha512':
      return CryptoJS.SHA512(msg).toString()
    case 'sha3-224':
      return sha3(msg, 224)
    case 'sha3-256':
      return sha3(msg, 256)
    case 'sha3-384':
      return sha3(msg, 384)
    case 'sha3-512':
      return sha3(msg, 512)
    case 'keccak256':
      return keccak(msg, 256)
    case 'ripemd160':
      return CryptoJS.RIPEMD160(msg).toString()
    case 'sm3':
      return sm3(msg)
    case 'crc32':
      return crc32(utf8ToBytes(msg))
    default:
      throw new Error(`未知的摘要算法：${algo}`)
  }
}

/** @returns {string} 小写 hex */
export function computeHmac (algo, text, keyText, keyFormat = 'utf8') {
  const msg = String(text ?? '')
  let keyBytes
  if (keyFormat === 'hex') keyBytes = hexToBytes(keyText)
  else if (keyFormat === 'base64') keyBytes = base64ToBytes(keyText)
  else keyBytes = utf8ToBytes(keyText)

  if (algo === 'sm3') {
    return sm3(msg, { key: bytesToHex(keyBytes) })
  }

  const helper = HMAC_HELPERS[algo]
  if (!helper || typeof CryptoJS[helper] !== 'function') {
    throw new Error(`不支持的 HMAC 算法：${algo}`)
  }
  return CryptoJS[helper](msg, bytesToWordArray(keyBytes)).toString()
}

/** 支持哪些 HMAC 算法（运行时探测，避免用到不存在的方法） */
export function availableHmacAlgorithms () {
  return HMAC_ALGORITHMS.filter((a) => a.id === 'sm3' || typeof CryptoJS[HMAC_HELPERS[a.id]] === 'function')
}
