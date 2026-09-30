import { JSEncrypt } from 'jsencrypt'
import smCrypto from 'sm-crypto'
import {
  CryptoJS,
  utf8ToBytes,
  bytesToUtf8,
  bytesToHex,
  hexToBytes,
  bytesToBase64,
  base64ToBytes,
  bytesToPem,
  pemToBytes,
  pemLabel,
  pkcs1ToPkcs8,
  pkcs8ToPkcs1,
  pkcs1PublicToSpki,
  spkiToPkcs1,
  rawSignatureToDer,
  derSignatureToRaw,
  sniffPrivateKey,
  sniffPublicKey,
} from './bytes.js'

const { sm2 } = smCrypto

/* =========================================================== PEM 归一化 */

/** 私钥 -> PKCS#8 DER（WebCrypto 要求） */
export function privateKeyDer (pem) {
  const der = pemToBytes(pem)
  const label = pemLabel(pem)
  if (/RSA PRIVATE KEY/.test(label)) return pkcs1ToPkcs8(der)
  if (/PRIVATE KEY/.test(label)) return der
  // 没有 PEM 头时按 DER 结构判断，避免把 PKCS#8 又包一层
  return sniffPrivateKey(der) === 'pkcs1' ? pkcs1ToPkcs8(der) : der
}

/** 公钥 -> SPKI DER（WebCrypto 要求） */
export function publicKeyDer (pem) {
  const der = pemToBytes(pem)
  const label = pemLabel(pem)
  if (/RSA PUBLIC KEY/.test(label)) return pkcs1PublicToSpki(der)
  if (/PUBLIC KEY/.test(label)) return der
  return sniffPublicKey(der) === 'pkcs1' ? pkcs1PublicToSpki(der) : der
}

/** 私钥 -> jsencrypt 能直接吃的 PKCS#1 PEM */
export function jsencryptPrivatePem (pem) {
  const label = pemLabel(pem)
  if (/RSA PRIVATE KEY/.test(label)) return pem
  const der = pemToBytes(pem)
  if (!/PRIVATE KEY/.test(label) && sniffPrivateKey(der) === 'pkcs1') return bytesToPem('RSA PRIVATE KEY', der)
  try {
    return bytesToPem('RSA PRIVATE KEY', pkcs8ToPkcs1(der))
  } catch (e) {
    return pem
  }
}

/** 公钥 -> jsencrypt 能直接吃的 SPKI PEM */
export function jsencryptPublicPem (pem) {
  const label = pemLabel(pem)
  if (/PUBLIC KEY/.test(label) && !/RSA PUBLIC KEY/.test(label)) return pem
  const der = pemToBytes(pem)
  if (!label && sniffPublicKey(der) === 'spki') return bytesToPem('PUBLIC KEY', der)
  try {
    return bytesToPem('PUBLIC KEY', pkcs1PublicToSpki(der))
  } catch (e) {
    return pem
  }
}

/* =========================================================== 通用 */

function subtle () {
  const c = globalThis.crypto
  if (!c || !c.subtle) {
    throw new Error('当前环境不支持 WebCrypto，请使用较新的 Chrome / Edge / Firefox，并通过 https 或 localhost 打开')
  }
  return c.subtle
}

export function webCryptoAvailable () {
  return !!(globalThis.crypto && globalThis.crypto.subtle)
}

const RSA_DIGESTS = [
  { id: 'sha256', label: 'SHA-256', helper: () => CryptoJS.SHA256, webName: 'SHA-256' },
  { id: 'sha1', label: 'SHA-1', helper: () => CryptoJS.SHA1, webName: 'SHA-1' },
  { id: 'sha512', label: 'SHA-512', helper: () => CryptoJS.SHA512, webName: 'SHA-512' },
  { id: 'md5', label: 'MD5', helper: () => CryptoJS.MD5, webName: null },
]

export function rsaDigest (id) {
  return RSA_DIGESTS.find((d) => d.id === id) || RSA_DIGESTS[0]
}

/* =========================================================== RSA */

/**
 * 生成 RSA 密钥对。
 * 优先使用 WebCrypto：它保证模数位数精确，而 jsencrypt 自带的生成器在 1024 位时
 * 会产出 1023 位的模数（实测 n.bitLength() === 1023），既不利于互通也略降强度。
 * @returns {Promise<{ publicKey: string, privateKey: string, bits: number }>}
 */
export async function generateRsaKeyPair (bits = 2048) {
  const size = [512, 1024, 2048, 4096].includes(Number(bits)) ? Number(bits) : 2048
  if (webCryptoAvailable()) {
    try {
      const pair = await subtle().generateKey(
        {
          name: 'RSA-OAEP',
          modulusLength: size,
          publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
          hash: 'SHA-256',
        },
        true,
        ['encrypt', 'decrypt']
      )
      const spki = new Uint8Array(await subtle().exportKey('spki', pair.publicKey))
      const pkcs8 = new Uint8Array(await subtle().exportKey('pkcs8', pair.privateKey))
      return {
        publicKey: bytesToPem('PUBLIC KEY', spki),
        privateKey: bytesToPem('PRIVATE KEY', pkcs8),
        bits: size,
      }
    } catch (e) {
      // 落到 jsencrypt
    }
  }
  const crypt = new JSEncrypt({ default_key_size: String(size) })
  const key = crypt.getKey()
  if (!key || !key.n) throw new Error('RSA 密钥生成失败')
  return {
    publicKey: crypt.getPublicKey(),
    privateKey: crypt.getPrivateKey(),
    bits: key.n.bitLength(),
  }
}

export function rsaMaxPlaintext (publicKeyPem, padding = 'pkcs1') {
  const crypt = new JSEncrypt()
  crypt.setPublicKey(publicKeyPem)
  const key = crypt.getKey()
  if (!key || !key.n) throw new Error('无法解析 RSA 公钥')
  const bytes = Math.floor(key.n.bitLength() / 8)
  return padding === 'oaep' ? bytes - 2 * 32 - 2 : bytes - 11
}

export function rsaEncrypt (plaintext, publicKeyPem, padding = 'pkcs1') {
  const text = String(plaintext)
  const max = rsaMaxPlaintext(publicKeyPem, padding)
  const byteLength = utf8ToBytes(text).length
  if (padding === 'pkcs1' && byteLength > max) {
    throw new Error(`明文过长：PKCS#1 v1.5 填充下该密钥最多加密 ${max} 字节，当前 ${byteLength} 字节。请改用对称加密，或先加密 AES 密钥。`)
  }
  if (padding === 'oaep') {
    return rsaOaepEncrypt(text, publicKeyPem)
  }
  const crypt = new JSEncrypt()
  crypt.setPublicKey(jsencryptPublicPem(publicKeyPem))
  const out = crypt.encrypt(text)
  if (out === false) throw new Error('RSA 加密失败，请检查公钥是否为合法的 PEM')
  return out
}

export function rsaDecrypt (ciphertext, privateKeyPem, padding = 'pkcs1') {
  if (padding === 'oaep') return rsaOaepDecrypt(ciphertext, privateKeyPem)
  const crypt = new JSEncrypt()
  crypt.setPrivateKey(jsencryptPrivatePem(privateKeyPem))
  const out = crypt.decrypt(String(ciphertext).trim())
  if (out === false || out === null) {
    throw new Error('RSA 解密失败：请检查私钥与密文是否匹配（也可能密文不是本工具的 PKCS#1 填充格式）')
  }
  return out
}

/* -------- RSA-OAEP（走 WebCrypto，与 OpenSSL / Java 互通） -------- */

async function importRsaKey (pem, usage) {
  const isPublic = pemLabel(pem).includes('PUBLIC')
  const der = isPublic ? publicKeyDer(pem) : privateKeyDer(pem)
  const algo = { name: 'RSA-OAEP', hash: 'SHA-256' }
  return subtle().importKey(isPublic ? 'spki' : 'pkcs8', der, algo, false, [usage])
}

export async function rsaOaepEncrypt (plaintext, publicKeyPem) {
  const key = await importRsaKey(publicKeyPem, 'encrypt')
  const buf = await subtle().encrypt({ name: 'RSA-OAEP' }, key, utf8ToBytes(String(plaintext)))
  return bytesToBase64(new Uint8Array(buf))
}

export async function rsaOaepDecrypt (ciphertextB64, privateKeyPem) {
  const key = await importRsaKey(privateKeyPem, 'decrypt')
  let buf
  try {
    buf = await subtle().decrypt({ name: 'RSA-OAEP' }, key, base64ToBytes(String(ciphertextB64).trim()))
  } catch (e) {
    throw new Error('RSA-OAEP 解密失败：私钥不匹配或密文已损坏')
  }
  return bytesToUtf8(new Uint8Array(buf))
}

/* -------- RSA 签名 / 验签 -------- */

export function rsaSign (text, privateKeyPem, digest = 'sha256') {
  const d = rsaDigest(digest)
  if (!d.webName) throw new Error('MD5 签名需要 jsencrypt 的摘要头，请改用 SHA-256')
  const crypt = new JSEncrypt()
  crypt.setPrivateKey(jsencryptPrivatePem(privateKeyPem))
  const sig = crypt.sign(String(text), d.helper(), digest)
  if (!sig) throw new Error('RSA 签名失败，请检查私钥')
  return sig
}

export function rsaVerify (text, signature, publicKeyPem, digest = 'sha256') {
  const d = rsaDigest(digest)
  const crypt = new JSEncrypt()
  crypt.setPublicKey(jsencryptPublicPem(publicKeyPem))
  return crypt.verify(String(text), String(signature).trim(), d.helper()) === true
}

/* =========================================================== ECDSA / Ed25519（WebCrypto） */

export const EC_CURVES = [
  { id: 'P-256', label: 'P-256 (secp256r1)', size: 32 },
  { id: 'P-384', label: 'P-384 (secp384r1)', size: 48 },
  { id: 'P-521', label: 'P-521 (secp521r1)', size: 66 },
]

export function ecCurve (id) {
  return EC_CURVES.find((c) => c.id === id) || EC_CURVES[0]
}

export const EC_SIGNATURE_FORMATS = [
  { id: 'raw', label: 'RAW (r‖s，Base64)' },
  { id: 'der', label: 'DER (ASN.1，Base64)' },
  { id: 'rawhex', label: 'RAW 十六进制' },
]

export const EC_HASHES = [
  { id: 'SHA-256', label: 'SHA-256' },
  { id: 'SHA-384', label: 'SHA-384' },
  { id: 'SHA-512', label: 'SHA-512' },
]

export function ecHash (id) {
  return EC_HASHES.find((h) => h.id === id) || EC_HASHES[0]
}

export async function generateEcKeyPair (curve = 'P-256') {
  const pair = await subtle().generateKey(
    { name: 'ECDSA', namedCurve: curve },
    true,
    ['sign', 'verify']
  )
  return exportEcKeyPair(pair, curve)
}

async function exportEcKeyPair (pair, curve) {
  const spki = new Uint8Array(await subtle().exportKey('spki', pair.publicKey))
  const pkcs8 = new Uint8Array(await subtle().exportKey('pkcs8', pair.privateKey))
  return {
    publicKey: bytesToPem('PUBLIC KEY', spki),
    privateKey: bytesToPem('PRIVATE KEY', pkcs8),
    curve,
  }
}

function signatureToOutput (raw, format, curveId) {
  const size = ecCurve(curveId).size
  if (format === 'der') return bytesToBase64(new Uint8Array(rawSignatureToDer(raw, size)))
  if (format === 'rawhex') return bytesToHex(raw)
  return bytesToBase64(raw)
}

function outputToSignature (text, format, curveId) {
  const size = ecCurve(curveId).size
  const raw = String(text).trim()
  if (format === 'der') return derSignatureToRaw(base64ToBytes(raw), size)
  if (format === 'rawhex') {
    const bytes = hexToBytes(raw)
    if (bytes.length !== size * 2) {
      throw new Error(`RAW 签名长度应为 ${size * 2} 字节，当前为 ${bytes.length} 字节`)
    }
    return bytes
  }
  const bytes = base64ToBytes(raw)
  if (bytes.length !== size * 2) {
    throw new Error(`RAW 签名长度应为 ${size * 2} 字节，当前为 ${bytes.length} 字节`)
  }
  return bytes
}

export async function ecdsaSign ({ text, privateKey, curve = 'P-256', hash = 'SHA-256', format = 'raw' }) {
  const key = await subtle().importKey(
    'pkcs8',
    privateKeyDer(privateKey),
    { name: 'ECDSA', namedCurve: curve },
    false,
    ['sign']
  )
  const raw = new Uint8Array(await subtle().sign({ name: 'ECDSA', hash }, key, utf8ToBytes(String(text))))
  return signatureToOutput(raw, format, curve)
}

export async function ecdsaVerify ({ text, signature, publicKey, curve = 'P-256', hash = 'SHA-256', format = 'raw' }) {
  const key = await subtle().importKey(
    'spki',
    publicKeyDer(publicKey),
    { name: 'ECDSA', namedCurve: curve },
    false,
    ['verify']
  )
  const raw = outputToSignature(signature, format, curve)
  try {
    return await subtle().verify({ name: 'ECDSA', hash }, key, raw, utf8ToBytes(String(text)))
  } catch (e) {
    throw new Error(`验签失败：签名格式或曲线不匹配（${e.message}）`)
  }
}

/* -------- Ed25519 -------- */

export async function ed25519Available () {
  try {
    await subtle().generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])
    return true
  } catch (e) {
    return false
  }
}

export async function generateEd25519KeyPair () {
  let pair
  try {
    pair = await subtle().generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])
  } catch (e) {
    throw new Error('当前浏览器不支持 Ed25519（需要 Chrome 113+ / Firefox 129+ / Safari 17+）')
  }
  const spki = new Uint8Array(await subtle().exportKey('spki', pair.publicKey))
  const pkcs8 = new Uint8Array(await subtle().exportKey('pkcs8', pair.privateKey))
  return { publicKey: bytesToPem('PUBLIC KEY', spki), privateKey: bytesToPem('PRIVATE KEY', pkcs8) }
}

export async function ed25519Sign (text, privateKey) {
  const key = await subtle().importKey(
    'pkcs8',
    privateKeyDer(privateKey),
    { name: 'Ed25519' },
    false,
    ['sign']
  )
  const sig = new Uint8Array(await subtle().sign({ name: 'Ed25519' }, key, utf8ToBytes(String(text))))
  return bytesToBase64(sig)
}

export async function ed25519Verify (text, signature, publicKey) {
  const key = await subtle().importKey(
    'spki',
    publicKeyDer(publicKey),
    { name: 'Ed25519' },
    false,
    ['verify']
  )
  const sig = base64ToBytes(String(signature).trim())
  if (sig.length !== 64) throw new Error(`Ed25519 签名长度应为 64 字节，当前为 ${sig.length} 字节`)
  return subtle().verify({ name: 'Ed25519' }, key, sig, utf8ToBytes(String(text)))
}

/* =========================================================== SM2 */

/**
 * 生成 SM2 密钥对（返回 hex 串，sm-crypto 的原生格式）
 */
export function generateSm2KeyPair () {
  const pair = sm2.generateKeyPairHex()
  return {
    publicKey: pair.publicKey,
    privateKey: pair.privateKey,
  }
}

/**
 * SM2 公钥归一化。
 * 标准互换格式是「04 + X + Y」共 130 位十六进制，但不少工具只给 128 位的 X‖Y，
 * 两种都接受，内部统一成 sm-crypto 习惯的 130 位带前缀形式。
 */
export function normalizeSm2PublicKey (publicKeyHex) {
  const hex = String(publicKeyHex).replace(/[\s:]/g, '')
  if (/^[0-9a-fA-F]{130}$/.test(hex)) {
    if (!hex.startsWith('04')) throw new Error('SM2 公钥的 130 位形式必须以 04 开头（未压缩点）')
    return hex
  }
  if (/^[0-9a-fA-F]{128}$/.test(hex)) return '04' + hex
  if (/^[0-9a-fA-F]{66}$/.test(hex)) {
    throw new Error('暂不支持 SM2 压缩公钥（02/03 开头），请使用未压缩公钥')
  }
  throw new Error('SM2 公钥应为 128 位（X‖Y）或 130 位（04‖X‖Y）十六进制')
}

export function sm2Encrypt (plaintext, publicKeyHex, mode = 1) {
  const text = String(plaintext)
  const out = sm2.doEncrypt(text, normalizeSm2PublicKey(publicKeyHex), mode)
  return out.startsWith('04') ? out : '04' + out
}

export function sm2Decrypt (cipherHex, privateKeyHex, mode = 1) {
  const hex = String(cipherHex).replace(/[\s:]/g, '')
  if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length % 2) {
    throw new Error('SM2 密文应为十六进制字符串')
  }
  // sm-crypto 内部把 C1 的 '04' 前缀去掉了，而标准互换格式带前缀。
  // 两种形式长度上无法区分（明文长度未知），所以都试一遍。
  const candidates = hex.startsWith('04') ? [hex.slice(2), hex] : [hex]
  for (const candidate of candidates) {
    try {
      const out = sm2.doDecrypt(candidate, String(privateKeyHex).trim(), mode, { output: 'string' })
      if (out) return out
    } catch (e) {
      // 继续尝试下一种
    }
  }
  throw new Error('SM2 解密失败：私钥与密文不匹配（也可能是密文格式 / C1C3C2 顺序不正确）')
}

/**
 * SM2 签名。注意：sm-crypto 在 der:true 时返回的就是 **十六进制字符串**，
 * 早期版本把它当成字节数组又转了一次 hex，导致签名永远无法验签。
 */
export function sm2Sign (text, privateKeyHex, { der = true } = {}) {
  const out = sm2.doSignature(String(text), String(privateKeyHex).trim(), { hash: true, der })
  return out
}

export function sm2Verify (text, signatureHex, publicKeyHex, { der = true } = {}) {
  const sig = String(signatureHex).replace(/\s/g, '')
  try {
    const key = normalizeSm2PublicKey(publicKeyHex)
    return sm2.doVerifySignature(String(text), sig, key, { hash: true, der }) === true
  } catch (e) {
    return false
  }
}

export function sm2PublicKeyFromPrivate (privateKeyHex) {
  return sm2.getPublicKeyFromPrivateKey(String(privateKeyHex).trim())
}

export function sm2ValidatePublicKey (publicKeyHex) {
  try {
    return sm2.verifyPublicKey(normalizeSm2PublicKey(publicKeyHex)) === true
  } catch (e) {
    return false
  }
}
