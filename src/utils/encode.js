import {
  utf8ToBytes,
  bytesToUtf8,
  bytesToHex,
  hexToBytes,
  bytesToBase64,
  base64ToBytes,
  bytesToBase64Url,
  base64UrlToBytes,
  isBase64,
} from './bytes.js'

/**
 * 纯文本编解码工具集。
 * 每个工具都是 { id, label, desc, canDecode, decodeLabel, encodeLabel, encode(text, opts), decode(text, opts) }
 */

export const ENCODE_TOOLS = [
  {
    id: 'encode-base64',
    label: 'Base64',
    desc: '把文本按 UTF-8 编码后再做 Base64（RFC 4648）',
    placeholder: 'Hello, World! 你好，世界！',
    decodePlaceholder: 'SGVsbG8sIFdvcmxkIQ==',
    encode: (text, opts) => (opts.lineBreak ? wrap75(bytesToBase64(utf8ToBytes(text))) : bytesToBase64(utf8ToBytes(text))),
    decode: (text) => bytesToUtf8(base64ToBytes(text)),
  },
  {
    id: 'encode-base64url',
    label: 'Base64URL',
    desc: 'URL 安全的 Base64：+ / 换成 - _，默认去掉 = 填充（JWT、URL 参数常用）',
    placeholder: 'https://example.com/?a=1&b=中文',
    decodePlaceholder: 'aHR0cHM6Ly9leGFtcGxlLmNvbS8_YT0xJmI9JUU0JUI4JUFEJUU2JTk2JTg3',
    encode: (text) => bytesToBase64Url(utf8ToBytes(text)),
    decode: (text) => bytesToUtf8(base64UrlToBytes(text)),
  },
  {
    id: 'encode-hex',
    label: 'Hex 十六进制',
    desc: '把文本按 UTF-8 编码后转成十六进制字符串',
    placeholder: 'Hello 你好',
    decodePlaceholder: '48656c6c6f20e4bda0e5a5bd',
    encode: (text, opts) => {
      const hex = bytesToHex(utf8ToBytes(text))
      return opts.upper ? hex.toUpperCase() : hex
    },
    decode: (text) => bytesToUtf8(hexToBytes(text)),
  },
  {
    id: 'encode-url',
    label: 'URL 编码',
    desc: 'encodeURIComponent / decodeURIComponent，用于 URL 参数',
    placeholder: 'https://例子.com/搜索?q=你好 世界',
    decodePlaceholder: 'https%3A%2F%2F%E4%BE%8B%E5%AD%90.com',
    encode: (text, opts) => (opts.component ? encodeURIComponent(text) : encodeURI(text)),
    decode: (text) => decodeURIComponent(text),
  },
  {
    id: 'encode-html',
    label: 'HTML 实体',
    desc: '转义 & < > " \' 等字符，防止 XSS / 显示异常',
    placeholder: '<script>alert("XSS & \'危险\'")</script>',
    decodePlaceholder: '&lt;b&gt;加粗&lt;/b&gt; &amp; &#39;引号&#39;',
    encode: (text) => escapeHtml(text),
    decode: (text) => unescapeHtml(text),
  },
  {
    id: 'encode-unicode',
    label: 'Unicode 转义',
    desc: '非 ASCII 字符转成 \\uXXXX（支持 emoji 等代理对）',
    placeholder: '中文 abc 😀',
    decodePlaceholder: '\\u4e2d\\u6587 abc \\ud83d\\ude00',
    encode: (text) => escapeUnicode(text),
    decode: (text) => unescapeUnicode(text),
  },
  {
    id: 'encode-binary',
    label: '二进制 / 位串',
    desc: '把每个字节展开成 8 位二进制（每 8 位一组，便于阅读）',
    placeholder: 'Hi',
    decodePlaceholder: '01001000 01101001',
    encode: (text) => Array.from(utf8ToBytes(text), (b) => b.toString(2).padStart(8, '0')).join(' '),
    decode: (text) => {
      const bits = text.replace(/[\s_]/g, '')
      if (!/^[01]*$/.test(bits) || bits.length % 8) {
        throw new Error('二进制串只能包含 0 和 1，且长度必须是 8 的整数倍')
      }
      const bytes = new Uint8Array(bits.length / 8)
      for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2)
      return bytesToUtf8(bytes)
    },
  },
  {
    id: 'encode-jwt',
    label: 'JWT 解析',
    desc: '解析（不解密）JWT 的头部与载荷，并给出常见时间字段的可读形式',
    canDecodeOnly: true,
    decodeOnly: true,
    decode: (text) => decodeJwt(text),
    encode: null,
    placeholder: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
  },
]

export function getEncodeTool (id) {
  return ENCODE_TOOLS.find((t) => t.id === id) || ENCODE_TOOLS[0]
}

/* ---------------------------------------------------------- 文本编解码 */

export function encodeText (toolId, text, opts = {}) {
  const tool = getEncodeTool(toolId)
  if (!tool.encode) throw new Error(`${tool.label} 仅支持解析（不支持反向编码）`)
  return tool.encode(text, opts)
}

export function decodeText (toolId, text) {
  const tool = getEncodeTool(toolId)
  return tool.decode(text)
}

function wrap75 (str) {
  return str.replace(/(.{76})/g, '$1\n')
}

/* ---------------------------------------------------------- HTML */

const HTML_ENTITIES = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
}

const NAMED_ENTITIES = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: '\u00a0',
  copy: '©', reg: '®', trade: '™', hellip: '…', mdash: '—', ndash: '–',
  lsquo: '‘', rsquo: '’', ldquo: '“', rdquo: '”', middot: '·', times: '×',
  divide: '÷', deg: '°', plusmn: '±', laquo: '«', raquo: '»', euro: '€',
  pound: '£', yen: '¥', sect: '§', para: '¶', bull: '•', dagger: '†',
}

export function escapeHtml (text) {
  return String(text).replace(/[&<>"']/g, (c) => HTML_ENTITIES[c])
}

export function unescapeHtml (text) {
  return String(text).replace(/&(#x?[0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]*);/g, (whole, body) => {
    if (body[0] === '#') {
      const isHex = body[1] === 'x' || body[1] === 'X'
      const code = parseInt(body.slice(isHex ? 2 : 1), isHex ? 16 : 10)
      if (!Number.isFinite(code) || code < 0 || code > 0x10ffff) return whole
      try {
        return String.fromCodePoint(code)
      } catch (e) {
        return whole
      }
    }
    const named = NAMED_ENTITIES[body]
    return named === undefined ? whole : named
  })
}

/* ---------------------------------------------------------- Unicode 转义 */

export function escapeUnicode (text) {
  let out = ''
  for (const ch of String(text)) {
    const cp = ch.codePointAt(0)
    if (cp < 0x20 || cp > 0x7e) {
      if (cp > 0xffff) {
        // 代理对：拆成两个 \uXXXX，与 JSON.stringify 行为一致
        const high = Math.floor((cp - 0x10000) / 0x400) + 0xd800
        const low = ((cp - 0x10000) % 0x400) + 0xdc00
        out += `\\u${high.toString(16).padStart(4, '0')}\\u${low.toString(16).padStart(4, '0')}`
      } else {
        out += `\\u${cp.toString(16).padStart(4, '0')}`
      }
    } else if (ch === '\\') {
      out += '\\\\'
    } else {
      out += ch
    }
  }
  return out
}

export function unescapeUnicode (text) {
  return String(text)
    .replace(/\\u\{([0-9a-fA-F]{1,6})\}/g, (m, hex) => String.fromCodePoint(parseInt(hex, 16)))
    .replace(/\\u([0-9a-fA-F]{4})/g, (m, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/\\x([0-9a-fA-F]{2})/g, (m, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/\\\\/g, '\\')
}

/* ---------------------------------------------------------- JWT */

export function decodeJwt (token) {
  const raw = String(token).trim()
  if (!raw) throw new Error('请输入 JWT')
  const parts = raw.split('.')
  if (parts.length !== 3) {
    throw new Error(`JWT 应该由 3 段（头部.载荷.签名）组成，当前有 ${parts.length} 段`)
  }
  const header = JSON.parse(bytesToUtf8(base64UrlToBytes(parts[0])))
  const payload = JSON.parse(bytesToUtf8(base64UrlToBytes(parts[1])))

  const lines = []
  lines.push('— 头部 Header —')
  lines.push(JSON.stringify(header, null, 2))
  lines.push('')
  lines.push('— 载荷 Payload —')
  lines.push(JSON.stringify(payload, null, 2))
  lines.push('')
  lines.push('— 签名 Signature —')
  lines.push(parts[2] || '(空)')
  lines.push('')

  const timeFields = [
    ['iat', '签发时间'],
    ['nbf', '生效时间'],
    ['exp', '过期时间'],
  ]
  const found = timeFields.filter(([k]) => typeof payload[k] === 'number')
  if (found.length) {
    lines.push('— 时间字段 —')
    for (const [key, label] of found) {
      const d = new Date(payload[key] * 1000)
      lines.push(`${label} ${key}: ${payload[key]}  →  ${formatLocal(d)}`)
    }
    if (typeof payload.exp === 'number') {
      const diff = payload.exp * 1000 - Date.now()
      lines.push(diff > 0 ? `状态: 还有 ${humanDuration(diff)} 过期` : `状态: 已于 ${humanDuration(-diff)}前过期`)
    }
  }
  lines.push('')
  lines.push(`算法 alg: ${header.alg ?? '(未声明)'}　类型 typ: ${header.typ ?? '(未声明)'}`)
  lines.push('注意：本工具只做 Base64URL 解码，不校验签名，请勿据此信任令牌内容。')
  return lines.join('\n')
}

function formatLocal (d) {
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

function humanDuration (ms) {
  const s = Math.floor(ms / 1000)
  const d = Math.floor(s / 86400)
  const h = Math.floor((s % 86400) / 3600)
  const m = Math.floor((s % 3600) / 60)
  if (d) return `${d} 天 ${h} 小时`
  if (h) return `${h} 小时 ${m} 分`
  if (m) return `${m} 分 ${s % 60} 秒`
  return `${s} 秒`
}

/* ---------------------------------------------------------- 合法性预检 */

export function precheckDecode (toolId, text) {
  const t = String(text).trim()
  if (!t) return '请输入需要解码的内容'
  switch (toolId) {
    case 'encode-base64':
      if (!isBase64(t)) return '不是合法的 Base64 字符串'
      return ''
    case 'encode-base64url':
      if (!/^[A-Za-z0-9\-_]*={0,2}$/.test(t)) return '不是合法的 Base64URL 字符串'
      return ''
    case 'encode-hex':
      if (!/^[0-9a-fA-F\s:]*$/.test(t)) return '十六进制串只能包含 0-9 a-f A-F'
      if (t.replace(/[\s:]/g, '').length % 2) return '十六进制串长度必须是偶数'
      return ''
    default:
      return ''
  }
}
