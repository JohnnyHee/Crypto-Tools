import { randomBytes, bytesToHex, bytesToBase64, bytesToBase64Url, bytesToUtf8 } from './bytes.js'

export const RANDOM_TOOLS = [
  { id: 'random-bytes', label: '随机字节' },
  { id: 'random-password', label: '随机密码' },
  { id: 'random-uuid', label: 'UUID / 唯一 ID' },
]

export function getRandomTool (id) {
  return RANDOM_TOOLS.find((t) => t.id === id) || RANDOM_TOOLS[0]
}

export const RANDOM_OUTPUT_FORMATS = [
  { id: 'hex', label: 'Hex' },
  { id: 'base64', label: 'Base64' },
  { id: 'base64url', label: 'Base64URL' },
  { id: 'utf8', label: '可打印字符' },
]

const PRINTABLE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{};:,.<>?/'

export function formatRandomBytes (bytes, format) {
  switch (format) {
    case 'base64':
      return bytesToBase64(bytes)
    case 'base64url':
      return bytesToBase64Url(bytes)
    case 'utf8':
      return Array.from(bytes, (b) => PRINTABLE[b % PRINTABLE.length]).join('')
    default:
      return bytesToHex(bytes)
  }
}

export const PASSWORD_SETS = {
  lower: 'abcdefghijklmnopqrstuvwxyz',
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digits: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{};:,.<>?',
}

const AMBIGUOUS = 'Il1O0o'

/** 无模偏差的随机整数（32 位拒绝采样） */
function randomInt (max) {
  if (max <= 0) throw new Error('取值范围必须大于 0')
  if (max === 1) return 0
  if (max > 0x100000000) throw new Error('randomInt 取值范围不能超过 2^32')
  const limit = Math.floor(0x100000000 / max) * max
  // 最多尝试 1000 次，避免极端情况下死循环
  for (let i = 0; i < 1000; i++) {
    const buf = randomBytes(4)
    const v = ((buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3]) >>> 0
    if (v < limit) return v % max
  }
  throw new Error('随机数生成失败')
}

/**
 * 生成随机密码
 * @returns {{ password: string, meta: string[] }}
 */
export function generatePassword ({
  length = 20,
  lower = true,
  upper = true,
  digits = true,
  symbols = true,
  avoidAmbiguous = true,
  requireEach = true,
} = {}) {
  let pools = []
  if (lower) pools.push(PASSWORD_SETS.lower)
  if (upper) pools.push(PASSWORD_SETS.upper)
  if (digits) pools.push(PASSWORD_SETS.digits)
  if (symbols) pools.push(PASSWORD_SETS.symbols)
  if (!pools.length) throw new Error('请至少选择一种字符类型')

  const clean = (s) => (avoidAmbiguous ? Array.from(s).filter((c) => !AMBIGUOUS.includes(c)).join('') : s)
  pools = pools.map(clean).filter((s) => s.length)

  const all = pools.join('')
  const len = Math.max(pools.length, Math.min(512, Math.floor(length) || 16))

  const chars = []
  if (requireEach) {
    for (const pool of pools) chars.push(pool[randomInt(pool.length)])
  }
  while (chars.length < len) chars.push(all[randomInt(all.length)])

  // 洗牌（Fisher–Yates）
  for (let i = chars.length - 1; i > 0; i--) {
    const j = randomInt(i + 1)
    const tmp = chars[i]
    chars[i] = chars[j]
    chars[j] = tmp
  }

  const password = chars.join('')
  const entropy = Math.round(len * Math.log2(all.length) * 10) / 10
  const meta = [
    `长度 ${len} 字符`,
    `字符池 ${all.length} 个（${avoidAmbiguous ? '已排除易混淆字符 ' + AMBIGUOUS : '未排除易混淆字符'}）`,
    `信息熵约 ${entropy} bit`,
    entropy < 60 ? '强度评估：偏弱，建议加长到 16 位以上并勾选全部字符类型' : entropy < 90 ? '强度评估：中等' : '强度评估：强',
  ]
  return { password, meta }
}

/* ---------------------------------------------------------- UUID */

export function uuidV4 () {
  const b = randomBytes(16)
  b[6] = (b[6] & 0x0f) | 0x40
  b[8] = (b[8] & 0x3f) | 0x80
  const hex = bytesToHex(b)
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}

export function uuidV7 () {
  const b = randomBytes(16)
  const ts = Date.now()
  b[0] = (ts / 2 ** 40) & 0xff
  b[1] = (ts / 2 ** 32) & 0xff
  b[2] = (ts / 2 ** 24) & 0xff
  b[3] = (ts / 2 ** 16) & 0xff
  b[4] = (ts / 2 ** 8) & 0xff
  b[5] = ts & 0xff
  b[6] = (b[6] & 0x0f) | 0x70
  b[8] = (b[8] & 0x3f) | 0x80
  const hex = bytesToHex(b)
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}

const ULID_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'

export function ulid () {
  let out = ''
  const ts = Date.now()
  let t = ts
  for (let i = 9; i >= 0; i--) {
    out = ULID_ALPHABET[t % 32] + out
    t = Math.floor(t / 32)
  }
  for (let i = 0; i < 16; i++) out += ULID_ALPHABET[randomInt(32)]
  return out
}

export function nanoid (size = 21) {
  const alphabet = 'useandom-26T198340PX75pxJACKVERYMINDBUSHWOLF_GQZbfghjklqvwyzrict'
  let id = ''
  for (let i = 0; i < size; i++) id += alphabet[randomInt(alphabet.length)]
  return id
}

/** base32 短 ID（无连字符） */
export function shortId (bytes = 12, upper = false) {
  const alphabet = (upper ? 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567' : 'abcdefghijklmnopqrstuvwxyz234567')
  const buf = randomBytes(bytes)
  return Array.from(buf, (b) => alphabet[b % alphabet.length]).join('')
}

export { bytesToUtf8 }
