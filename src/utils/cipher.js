/**
 * 对称加密
 *
 * 关键修复（对应旧版的真实缺陷）：
 *
 * 1. 旧版把密钥以「字符串口令」形式传给 crypto-js，会走 OpenSSL 的
 *    EVP_BytesToKey 派生：`cfg.iv = derivedParams.iv` 会把调用方传入的
 *    IV 直接覆盖掉，并且每次加密随机生成 salt，输出以 "Salted__" 开头、
 *    结果不可复现——界面上"支持自定义 IV"和显示的"使用的 IV"都是假的。
 *    现在统一先转成 Uint8Array/WordArray 再传入，走 SerializableCipher，
 *    用户指定的 IV 才真正生效，密文也不带 salt。
 *
 * 2. 旧版 SM4 没有传 options，sm-crypto 默认走 ECB，且密钥是 MD5 派生的
 *    字符串；现在补齐 ECB/CBC、IV 校验和密钥长度校验。
 */
import CryptoJS from 'crypto-js'
import smCrypto from 'sm-crypto'
import {
  bytesToHex,
  hexToBytes,
  bytesToBase64,
  base64ToBytes,
  utf8ToBytes,
  bytesToUtf8,
  bytesToWordArray,
  wordArrayToBytes,
  randomBytes,
} from './bytes.js'

const { sm4: SM4 } = smCrypto

/* ---------------------------------------------------------- 算法表 */

export const SYMMETRIC_ALGOS = {
  'cipher-aes': {
    label: 'AES',
    impl: 'cryptojs',
    cipher: CryptoJS.AES,
    blockSize: 16,
    ivSize: 16,
    keySizes: [16, 24, 32],
    keyHint: '16 / 24 / 32 字节（对应 AES-128 / 192 / 256）',
    defaultKeyText: '0123456789abcdef',
  },
  'cipher-des': {
    label: 'DES',
    impl: 'cryptojs',
    cipher: CryptoJS.DES,
    blockSize: 8,
    ivSize: 8,
    keySizes: [8],
    keyHint: '8 字节（DES 已不安全，仅用于兼容旧系统）',
    defaultKeyText: '12345678',
  },
  'cipher-tripledes': {
    label: '3DES',
    impl: 'cryptojs',
    cipher: CryptoJS.TripleDES,
    blockSize: 8,
    ivSize: 8,
    keySizes: [16, 24],
    keyHint: '24 字节（三密钥）或 16 字节（两密钥 K1/K2/K1）',
    defaultKeyText: '0123456789abcdef01234567',
  },
  'cipher-blowfish': {
    label: 'Blowfish',
    impl: 'cryptojs',
    cipher: CryptoJS.Blowfish,
    blockSize: 8,
    ivSize: 8,
    keySizes: [16],
    flexibleKey: true,
    maxKeySize: 56,
    keyHint: '4 – 56 字节，建议 16 字节',
    defaultKeyText: '0123456789abcdef',
  },
  'cipher-rc4': {
    label: 'RC4',
    impl: 'cryptojs',
    cipher: CryptoJS.RC4,
    stream: true,
    blockSize: 1,
    keySizes: [],
    flexibleKey: true,
    maxKeySize: 256,
    keyHint: '任意长度（1 – 256 字节）；RC4 已被证明不安全',
    defaultKeyText: '0123456789abcdef',
  },
  'cipher-rc4drop': {
    label: 'RC4Drop',
    impl: 'cryptojs',
    cipher: CryptoJS.RC4Drop,
    stream: true,
    blockSize: 1,
    keySizes: [],
    flexibleKey: true,
    maxKeySize: 256,
    keyHint: '任意长度（1 – 256 字节），丢弃前 768 字节密钥流',
    defaultKeyText: '0123456789abcdef',
  },
  'cipher-rabbit': {
    label: 'Rabbit',
    impl: 'cryptojs',
    cipher: CryptoJS.Rabbit,
    stream: true,
    blockSize: 1,
    ivSize: 8,
    optionalIV: true,
    keySizes: [16],
    keyHint: '16 字节（128 位）',
    defaultKeyText: '0123456789abcdef',
  },
  'cipher-sm4': {
    label: 'SM4',
    impl: 'sm4',
    blockSize: 16,
    ivSize: 16,
    keySizes: [16],
    modes: ['CBC', 'ECB'],
    keyHint: '16 字节（国密 GB/T 32907-2016）',
    defaultKeyText: '0123456789abcdef',
  },
}

export const CIPHER_MODES = [
  { id: 'CBC', label: 'CBC', desc: '密码分组链接：需要 IV，最常用' },
  { id: 'ECB', label: 'ECB', desc: '电码本：不需要 IV，相同明文块产生相同密文块，不推荐' },
  { id: 'CFB', label: 'CFB', desc: '密文反馈：需要 IV' },
  { id: 'OFB', label: 'OFB', desc: '输出反馈：需要 IV' },
  { id: 'CTR', label: 'CTR', desc: '计数器模式：需要 IV' },
  { id: 'CTRGladman', label: 'CTR (Gladman)', desc: '另一种计数器实现' },
]

export const CIPHER_PADDINGS = [
  { id: 'Pkcs7', label: 'PKCS#7', desc: '标准填充（默认），sm-crypto 仅支持此填充' },
  { id: 'ZeroPadding', label: 'ZeroPadding', desc: '以 0x00 补齐' },
  { id: 'AnsiX923', label: 'ANSI X9.23', desc: '以 0 填充，末字节记录填充长度' },
  { id: 'Iso10126', label: 'ISO 10126', desc: '随机字节填充' },
  { id: 'Iso97971', label: 'ISO/IEC 9797-1', desc: '0x80 后补 0' },
  { id: 'NoPadding', label: '不填充', desc: '要求数据长度恰为分组大小的整数倍' },
]

const CRYPTOJS_MODES = {
  CBC: CryptoJS.mode.CBC,
  ECB: CryptoJS.mode.ECB,
  CFB: CryptoJS.mode.CFB,
  OFB: CryptoJS.mode.OFB,
  CTR: CryptoJS.mode.CTR,
  CTRGladman: CryptoJS.mode.CTRGladman,
}

const CRYPTOJS_PADDINGS = {
  Pkcs7: CryptoJS.pad.Pkcs7,
  ZeroPadding: CryptoJS.pad.ZeroPadding,
  AnsiX923: CryptoJS.pad.AnsiX923,
  Iso10126: CryptoJS.pad.Iso10126,
  Iso97971: CryptoJS.pad.Iso97971,
  NoPadding: CryptoJS.pad.NoPadding,
}

export const KEY_FORMATS = [
  { id: 'utf8', label: 'UTF-8 文本', desc: '按 UTF-8 转成字节' },
  { id: 'hex', label: 'Hex', desc: '十六进制字符串' },
  { id: 'base64', label: 'Base64', desc: 'Base64 字符串' },
  { id: 'md5', label: 'MD5 派生', desc: 'MD5(口令) 得到 16 字节密钥' },
  { id: 'sha256', label: 'SHA256 派生', desc: 'SHA256(口令) 得到 32 字节密钥' },
]

const DERIVED_FORMATS = ['md5', 'sha256']

/* ---------------------------------------------------------- 密钥 / IV */

export function getAlgo (algoId) {
  const spec = SYMMETRIC_ALGOS[algoId]
  if (!spec) throw new Error(`未知的对称算法：${algoId}`)
  return spec
}

/** 该算法在 UI 中可选的模式（流密码不涉及分组模式） */
export function modesForAlgo (algoId) {
  const spec = SYMMETRIC_ALGOS[algoId]
  if (!spec || spec.stream) return []
  const allowed = spec.modes || CIPHER_MODES.map((m) => m.id)
  return CIPHER_MODES.filter((m) => allowed.includes(m.id))
}

/** 该算法在 UI 中可选的填充方式（流密码不涉及填充） */
export function paddingsForAlgo (algoId) {
  const spec = SYMMETRIC_ALGOS[algoId]
  if (!spec || spec.stream) return []
  if (spec.impl === 'sm4') return CIPHER_PADDINGS.filter((p) => p.id === 'Pkcs7')
  return CIPHER_PADDINGS
}

function assertModeSupported (spec, mode) {
  if (spec.stream) return
  if (spec.modes && !spec.modes.includes(mode)) {
    throw new Error(`${spec.label} 仅支持 ${spec.modes.join(' / ')} 模式`)
  }
}

function assertPaddingSupported (spec, padding) {
  if (spec.stream) return
  if (spec.impl === 'sm4' && padding !== 'Pkcs7') {
    throw new Error('SM4 底层仅支持 PKCS#7 填充')
  }
}

/** 按指定格式把输入文本转成密钥字节 */
export function deriveKeyBytes (text, format) {
  switch (format) {
    case 'utf8':
      return utf8ToBytes(text)
    case 'hex':
      return hexToBytes(text)
    case 'base64':
      return base64ToBytes(text)
    case 'md5':
      return wordArrayToBytes(CryptoJS.MD5(String(text)))
    case 'sha256':
      return wordArrayToBytes(CryptoJS.SHA256(String(text)))
    default:
      throw new Error(`未知的密钥格式：${format}`)
  }
}

/**
 * 把密钥字节调整为算法要求的长度
 * @returns {Uint8Array}
 */
export function fitKeyBytes (algoId, bytes, format) {
  const spec = getAlgo(algoId)
  if (bytes.length === 0) throw new Error('密钥不能为空')

  if (spec.flexibleKey) {
    const max = spec.maxKeySize || 56
    if (bytes.length > max) {
      throw new Error(`${spec.label} 密钥最长 ${max} 字节，当前 ${bytes.length} 字节`)
    }
    return bytes
  }

  if (DERIVED_FORMATS.includes(format)) {
    // 派生得到的密钥按"不超过实际长度的最大可用长度"截断
    const target = [...spec.keySizes].sort((a, b) => b - a).find((s) => s <= bytes.length)
    if (!target) {
      throw new Error(
        `${spec.label} 的密钥至少要 ${spec.keySizes[0]} 字节，${format.toUpperCase()} 派生只有 ${bytes.length} 字节`
      )
    }
    return bytes.subarray(0, target)
  }

  if (!spec.keySizes.includes(bytes.length)) {
    throw new Error(
      `${spec.label} 的密钥长度必须为 ${spec.keySizes.join(' / ')} 字节，当前为 ${bytes.length} 字节`
    )
  }
  return bytes
}

/** 解析 IV；mode 为 ECB 或算法无 IV 时返回空数组 */
export function deriveIvBytes (algoId, text, format, mode) {
  const spec = getAlgo(algoId)
  if (!spec.ivSize || mode === 'ECB') return new Uint8Array(0)
  if (!String(text).trim()) {
    if (spec.optionalIV) return new Uint8Array(0)
    throw new Error(`${spec.label} 的 ${mode} 模式需要 IV（初始向量）`)
  }
  let bytes
  switch (format) {
    case 'hex':
      bytes = hexToBytes(text)
      break
    case 'base64':
      bytes = base64ToBytes(text)
      break
    case 'utf8':
    default:
      bytes = utf8ToBytes(text)
      break
  }
  if (bytes.length !== spec.ivSize) {
    throw new Error(`IV 必须为 ${spec.ivSize} 字节，当前为 ${bytes.length} 字节`)
  }
  return bytes
}

export function randomIvHex (algoId) {
  const spec = getAlgo(algoId)
  return bytesToHex(randomBytes(spec.ivSize || 16))
}

/* ---------------------------------------------------------- 加解密 */

const PAD_ERR = '解密失败：填充校验未通过，通常是密钥 / IV / 模式 / 填充方式不正确'

/**
 * 按指定填充方案校验并去除填充。
 * 注意：调用 crypto-js 解密时强制使用 NoPadding，所以这里拿到的是**仍带填充**的明文，
 * 由本函数完成校验——这样才能真正识别出"密钥错误"的情况。
 */
function unpad (bytes, padding, blockSize) {
  if (padding === 'NoPadding') return bytes
  if (bytes.length === 0 || bytes.length % blockSize !== 0) {
    throw new Error('解密失败：数据长度不是分组大小的整数倍，请检查密文、密钥与模式')
  }
  switch (padding) {
    case 'Pkcs7': {
      const n = bytes[bytes.length - 1]
      if (n < 1 || n > blockSize) throw new Error(PAD_ERR)
      for (let i = 1; i <= n; i++) {
        if (bytes[bytes.length - i] !== n) throw new Error(PAD_ERR)
      }
      return bytes.subarray(0, bytes.length - n)
    }
    case 'AnsiX923': {
      const n = bytes[bytes.length - 1]
      if (n < 1 || n > blockSize) throw new Error(PAD_ERR)
      for (let i = 2; i <= n; i++) {
        if (bytes[bytes.length - i] !== 0) throw new Error(PAD_ERR)
      }
      return bytes.subarray(0, bytes.length - n)
    }
    case 'Iso10126': {
      const n = bytes[bytes.length - 1]
      if (n < 1 || n > blockSize) throw new Error(PAD_ERR)
      return bytes.subarray(0, bytes.length - n)
    }
    case 'Iso97971': {
      let i = bytes.length - 1
      while (i >= 0 && bytes[i] === 0) i--
      if (bytes[i] !== 0x80) throw new Error(PAD_ERR)
      return bytes.subarray(0, i)
    }
    case 'ZeroPadding': {
      let n = bytes.length
      while (n > 0 && bytes[n - 1] === 0) n--
      return bytes.subarray(0, n)
    }
    default:
      return bytes
  }
}

function cryptoJsCfg (spec, mode, padding, ivBytes, forDecrypt = false) {
  const cfg = {}
  if (!spec.stream) {
    assertModeSupported(spec, mode)
    cfg.mode = CRYPTOJS_MODES[mode] || CryptoJS.mode.CBC
    // 解密时一律 NoPadding：由 unpad() 手工校验，避免 crypto-js 静默吞掉填充错误
    cfg.padding = forDecrypt ? CryptoJS.pad.NoPadding : CRYPTOJS_PADDINGS[padding] || CryptoJS.pad.Pkcs7
  }
  if (spec.ivSize && ivBytes && ivBytes.length) cfg.iv = bytesToWordArray(ivBytes)
  return cfg
}

function decodeInput (text, encoding) {
  if (encoding === 'hex') return hexToBytes(text)
  if (encoding === 'base64') return base64ToBytes(text)
  return utf8ToBytes(text)
}

/**
 * 加密
 * @returns {string} Base64 或 Hex
 */
export function encryptSymmetric ({
  algoId,
  keyBytes,
  ivBytes,
  mode,
  padding,
  plaintext,
  plaintextEncoding = 'utf8',
  outputEncoding = 'base64',
}) {
  const spec = getAlgo(algoId)
  const text = String(plaintext ?? '')
  assertModeSupported(spec, mode)
  assertPaddingSupported(spec, padding)

  if (spec.impl === 'sm4') {
    const input = plaintextEncoding === 'utf8' ? text : Array.from(decodeInput(text, plaintextEncoding))
    const options = { padding: 'pkcs#7' }
    if (mode === 'CBC' || (mode !== 'ECB' && ivBytes.length)) {
      options.mode = 'cbc'
      options.iv = bytesToHex(ivBytes)
    }
    const hex = SM4.encrypt(input, bytesToHex(keyBytes), options)
    return outputEncoding === 'hex' ? hex : bytesToBase64(hexToBytes(hex))
  }

  const messageBytes = plaintextEncoding === 'utf8' ? utf8ToBytes(text) : decodeInput(text, plaintextEncoding)
  const message = plaintextEncoding === 'utf8' ? text : bytesToWordArray(messageBytes)

  if (!spec.stream && padding === 'NoPadding' && messageBytes.length % spec.blockSize !== 0) {
    throw new Error(
      `选择"不填充"时，明文长度必须是 ${spec.blockSize} 字节的整数倍（当前 ${messageBytes.length} 字节）`
    )
  }

  const encrypted = spec.cipher.encrypt(message, bytesToWordArray(keyBytes), cryptoJsCfg(spec, mode, padding, ivBytes))
  return outputEncoding === 'hex'
    ? CryptoJS.enc.Hex.stringify(encrypted.ciphertext)
    : CryptoJS.enc.Base64.stringify(encrypted.ciphertext)
}

/**
 * 解密
 * @returns {{ bytes: Uint8Array, text: string }}
 */
export function decryptSymmetric ({
  algoId,
  keyBytes,
  ivBytes,
  mode,
  padding,
  ciphertext,
  inputEncoding = 'base64',
}) {
  const spec = getAlgo(algoId)
  const input = String(ciphertext ?? '').trim()
  if (!input) throw new Error('请输入要解密的密文')
  assertModeSupported(spec, mode)
  assertPaddingSupported(spec, padding)

  if (spec.impl === 'sm4') {
    let hex = input.replace(/[\s:]/g, '')
    if (inputEncoding === 'base64') hex = bytesToHex(base64ToBytes(input))
    if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2) {
      throw new Error('密文不是合法的十六进制字符串')
    }
    const options = { padding: 'pkcs#7', output: 'array' }
    if (mode === 'CBC' || (mode !== 'ECB' && ivBytes.length)) {
      options.mode = 'cbc'
      options.iv = bytesToHex(ivBytes)
    }
    let arr
    try {
      arr = SM4.decrypt(hex, bytesToHex(keyBytes), options)
    } catch (e) {
      throw new Error(`SM4 解密失败：${e.message}`)
    }
    const bytes = Uint8Array.from(arr)
    return { bytes, text: safeUtf8(bytes) }
  }

  let cipherParams
  if (inputEncoding === 'hex') {
    cipherParams = CryptoJS.lib.CipherParams.create({ ciphertext: CryptoJS.enc.Hex.parse(input) })
  } else {
    cipherParams = CryptoJS.lib.CipherParams.create({ ciphertext: CryptoJS.enc.Base64.parse(input) })
  }

  let plainWA
  try {
    plainWA = spec.cipher.decrypt(
      cipherParams,
      bytesToWordArray(keyBytes),
      cryptoJsCfg(spec, mode, padding, ivBytes, true)
    )
  } catch (e) {
    throw new Error(`解密失败：${e.message}`)
  }
  let bytes = wordArrayToBytes(plainWA)
  bytes = unpad(bytes, spec.stream ? 'NoPadding' : padding, spec.blockSize)

  return { bytes, text: safeUtf8(bytes) }
}

function safeUtf8 (bytes) {
  try {
    return bytesToUtf8(bytes)
  } catch (e) {
    return ''
  }
}

export function bytesToEncoded (bytes, encoding) {
  if (encoding === 'hex') return bytesToHex(bytes)
  if (encoding === 'base64') return bytesToBase64(bytes)
  return bytesToUtf8(bytes)
}
