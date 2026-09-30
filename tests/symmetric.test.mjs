import { computeHash, computeHmac, availableHmacAlgorithms, sha3, keccak } from '../src/utils/hash.js'
import {
  encryptSymmetric, decryptSymmetric, deriveKeyBytes, fitKeyBytes, deriveIvBytes,
  SYMMETRIC_ALGOS, CIPHER_MODES, modesForAlgo, paddingsForAlgo,
} from '../src/utils/cipher.js'
import { hexToBytes, bytesToHex, rawSignatureToDer, derSignatureToRaw } from '../src/utils/bytes.js'

let pass = 0, fail = 0
const failures = []
const QUIET = !!process.env.QUIET
const ok = (name, cond, extra = '') => {
  if (cond) { pass++; if (!QUIET) console.log(`  ok   ${name}`) } else { fail++; failures.push(`${name} ${extra}`) }
}
const log = (...a) => console.log(...a)

log('\n== 摘要向量 ==')
ok('MD5("abc")', computeHash('md5', 'abc') === '900150983cd24fb0d6963f7d28e17f72')
ok('SHA1("abc")', computeHash('sha1', 'abc') === 'a9993e364706816aba3e25717850c26c9cd0d89d')
ok('SHA256("abc")', computeHash('sha256', 'abc') === 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
ok('SHA224("abc")', computeHash('sha224', 'abc') === '23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7')
ok('SHA384("abc")', computeHash('sha384', 'abc') === 'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7')
ok('SHA512("abc")', computeHash('sha512', 'abc') === 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f')
ok('SHA3-224("abc")', computeHash('sha3-224', 'abc') === 'e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf')
ok('SHA3-256("abc")', computeHash('sha3-256', 'abc') === '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532')
ok('SHA3-256("")', computeHash('sha3-256', '') === 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a')
ok('SHA3-384("abc")', computeHash('sha3-384', 'abc') === 'ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25')
ok('SHA3-512("abc")', computeHash('sha3-512', 'abc') === 'b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0')
ok('Keccak-256("abc")', computeHash('keccak256', 'abc') === '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45')
ok('Keccak-256("")', keccak('', 256) === 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470')
ok('RIPEMD160("abc")', computeHash('ripemd160', 'abc') === '8eb208f7e05d987a9b044a8e98c6b087f15a0bfc')
ok('SM3("abc")', computeHash('sm3', 'abc') === '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0')
ok('CRC32("123456789")', computeHash('crc32', '123456789') === 'cbf43926')
ok('CRC32("The quick brown fox jumps over the lazy dog")', computeHash('crc32', 'The quick brown fox jumps over the lazy dog') === '414fa339')
ok('SHA3-256 长输入长度', computeHash('sha3-256', 'a'.repeat(1000)) === '8f3934e6f7a15698fe0f396b95d8c4440929a8fa6eae140171c068b4549fbf81')

log('\n== HMAC ==')
log('  可用 HMAC:', availableHmacAlgorithms().map((a) => a.label).join(', '))
ok('HMAC-SHA256', computeHmac('sha256', 'msg', 'key') === '2d93cbc1be167bcb1637a4a23cbff01a7878f0c50ee833954ea5221bb1b8c628')
ok('HMAC-SM3', computeHmac('sm3', 'msg', 'key') === 'aaef27f7826f0b502a7e3d787a7ac6ee15a4ce44e2631200df14c54bc4f57fa7')
ok('HMAC-MD5', typeof computeHmac('md5', 'msg', 'key') === 'string' && computeHmac('md5', 'msg', 'key').length === 32)
ok('HMAC-SHA224', computeHmac('sha224', 'msg', 'key').length === 56)
ok('HMAC-SHA384', computeHmac('sha384', 'msg', 'key').length === 96)
ok('HMAC-RIPEMD160', computeHmac('ripemd160', 'msg', 'key').length === 40)

log('\n== AES 官方向量（NIST SP 800-38A） ==')
const aesKey128 = hexToBytes('2b7e151628aed2a6abf7158809cf4f3c')
const iv = hexToBytes('000102030405060708090a0b0c0d0e0f')
const ct1 = encryptSymmetric({
  algoId: 'cipher-aes', keyBytes: aesKey128, ivBytes: iv, mode: 'CBC', padding: 'NoPadding',
  plaintext: '6bc1bee22e409f96e93d7e117393172a', plaintextEncoding: 'hex', outputEncoding: 'hex',
})
ok('AES-128-CBC F.2.1 第1块', ct1 === '7649abac8119b246cee98e9b12e9197d', ct1)
// F.2.1 第2块：C2 = E(P2 XOR C1)，直接把前两块一起加密验证链式
ok('AES-128-CBC F.2.1 前2块', encryptSymmetric({
  algoId: 'cipher-aes', keyBytes: aesKey128, ivBytes: iv, mode: 'CBC', padding: 'NoPadding',
  plaintext: '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51', plaintextEncoding: 'hex', outputEncoding: 'hex',
}) === '7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2')
ok('AES-128-ECB F.1.1', encryptSymmetric({
  algoId: 'cipher-aes', keyBytes: aesKey128, ivBytes: new Uint8Array(0), mode: 'ECB', padding: 'NoPadding',
  plaintext: '6bc1bee22e409f96e93d7e117393172a', plaintextEncoding: 'hex', outputEncoding: 'hex',
}) === '3ad77bb40d7a3660a89ecaf32466ef97')
const aesKey256 = hexToBytes('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4')
ok('AES-256-CBC F.2.5', encryptSymmetric({
  algoId: 'cipher-aes', keyBytes: aesKey256, ivBytes: iv, mode: 'CBC', padding: 'NoPadding',
  plaintext: '6bc1bee22e409f96e93d7e117393172a', plaintextEncoding: 'hex', outputEncoding: 'hex',
}) === 'f58c4c04d6e5f1ba779eabfb5f7bfbd6')
ok('AES-256-CTR F.5.5', encryptSymmetric({
  algoId: 'cipher-aes', keyBytes: aesKey256, ivBytes: hexToBytes('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'), mode: 'CTR', padding: 'NoPadding',
  plaintext: '6bc1bee22e409f96e93d7e117393172a', plaintextEncoding: 'hex', outputEncoding: 'hex',
}) === '601ec313775789a5b7a7f504bbf3d228')
// 解密回环
const rt = decryptSymmetric({
  algoId: 'cipher-aes', keyBytes: aesKey128, ivBytes: iv, mode: 'CBC', padding: 'NoPadding',
  ciphertext: '7649abac8119b246cee98e9b12e9197d', inputEncoding: 'hex',
})
ok('AES-128-CBC 解密回环', bytesToHex(rt.bytes) === '6bc1bee22e409f96e93d7e117393172a', bytesToHex(rt.bytes))

log('\n== SM4 国标向量（GB/T 32907-2016 附录A） ==')
const sm4Key = hexToBytes('0123456789abcdeffedcba9876543210')
// GB/T 32907 附录A 只给单块 ECB 结果 681edf34…；此实现恒用 PKCS#7，
// 故 16 字节明文 -> 32 字节密文（前 16 字节应等于官方单块值）
const sm4One = encryptSymmetric({
  algoId: 'cipher-sm4', keyBytes: sm4Key, ivBytes: new Uint8Array(0), mode: 'ECB', padding: 'Pkcs7',
  plaintext: '0123456789abcdeffedcba9876543210', plaintextEncoding: 'hex', outputEncoding: 'hex',
})
ok('SM4-ECB 首分组 = 681edf34…', sm4One.slice(0, 32) === '681edf34d206965e86b3e94f536e4246', sm4One)
ok('SM4-ECB 带填充长度 32 字节', sm4One.length === 64, String(sm4One.length / 2))
ok('SM4 不支持 CFB', (() => {
  try {
    encryptSymmetric({ algoId: 'cipher-sm4', keyBytes: sm4Key, ivBytes: sm4Key, mode: 'CFB', padding: 'Pkcs7', plaintext: 'x' })
    return false
  } catch (e) { return /仅支持/.test(e.message) }
})())
const sm4Cbc = encryptSymmetric({
  algoId: 'cipher-sm4', keyBytes: sm4Key, ivBytes: sm4Key, mode: 'CBC', padding: 'Pkcs7',
  plaintext: '中文测试 hello', outputEncoding: 'hex',
})
const sm4Rt = decryptSymmetric({
  algoId: 'cipher-sm4', keyBytes: sm4Key, ivBytes: sm4Key, mode: 'CBC', padding: 'Pkcs7',
  ciphertext: sm4Cbc, inputEncoding: 'hex',
})
ok('SM4-CBC 往返', sm4Rt.text === '中文测试 hello', JSON.stringify(sm4Rt.text))
const sm4Ec = encryptSymmetric({
  algoId: 'cipher-sm4', keyBytes: sm4Key, ivBytes: new Uint8Array(0), mode: 'ECB', padding: 'Pkcs7',
  plaintext: '中文测试 hello', outputEncoding: 'base64',
})
ok('SM4-ECB base64 往返', decryptSymmetric({
  algoId: 'cipher-sm4', keyBytes: sm4Key, ivBytes: new Uint8Array(0), mode: 'ECB', padding: 'Pkcs7',
  ciphertext: sm4Ec, inputEncoding: 'base64',
}).text === '中文测试 hello')

log('\n== 全部算法 / 模式 往返 ==')
for (const [algoId, spec] of Object.entries(SYMMETRIC_ALGOS)) {
  const keyBytes = fitKeyBytes(algoId, deriveKeyBytes(spec.defaultKeyText, 'utf8'), 'utf8')
  const ivSize = spec.ivSize || 0
  const ivBytes = ivSize ? hexToBytes('0102030405060708090a0b0c0d0e0f10'.slice(0, ivSize * 2)) : new Uint8Array(0)
  const modes = spec.stream ? ['—'] : modesForAlgo(algoId).map((m) => m.id)
  for (const mode of modes) {
    const useIV = mode === 'ECB' ? new Uint8Array(0) : ivBytes
    try {
      const ct = encryptSymmetric({ algoId, keyBytes, ivBytes: useIV, mode, padding: 'Pkcs7', plaintext: 'Hello 世界 123' })
      const pt = decryptSymmetric({ algoId, keyBytes, ivBytes: useIV, mode, padding: 'Pkcs7', ciphertext: ct, inputEncoding: 'base64' })
      ok(`${spec.label} ${mode} 往返`, pt.text === 'Hello 世界 123', JSON.stringify(pt.text))
    } catch (e) {
      ok(`${spec.label} ${mode} 往返`, false, e.message)
    }
  }
  // 非 PKCS#7 填充往返
  if (!spec.stream) {
    for (const p of ['ZeroPadding', 'AnsiX923', 'Iso10126', 'Iso97971', 'NoPadding']) {
      if (!paddingsForAlgo(algoId).some((x) => x.id === p)) {
        ok(`${spec.label} 拒绝 ${p}`, (() => {
          try { encryptSymmetric({ algoId, keyBytes, ivBytes, mode: 'CBC', padding: p, plaintext: 'abc' }); return false } catch (e) { return /仅支持/.test(e.message) }
        })())
        continue
      }
      const ptText = p === 'NoPadding' ? '0123456789abcdef' : 'Hello 世界 123'
      try {
        const ct = encryptSymmetric({ algoId, keyBytes, ivBytes: ivBytes, mode: 'CBC', padding: p, plaintext: ptText })
        const pt = decryptSymmetric({ algoId, keyBytes, ivBytes: ivBytes, mode: 'CBC', padding: p, ciphertext: ct, inputEncoding: 'base64' })
        ok(`${spec.label} CBC + ${p} 往返`, pt.text === ptText, JSON.stringify(pt.text))
      } catch (e) { ok(`${spec.label} CBC + ${p} 往返`, false, e.message) }
    }
  }
}

log('\n== 密钥格式 / 派生长度 ==')
for (const fmt of ['utf8', 'hex', 'base64', 'md5', 'sha256']) {
  try {
    const raw = fmt === 'md5' || fmt === 'sha256' ? 'my-password' : fmt === 'hex' ? '00112233445566778899aabbccddeeff' : fmt === 'base64' ? 'AAECAwQFBgcICQoLDA0ODw==' : '0123456789abcdef'
    const b = fitKeyBytes('cipher-aes', deriveKeyBytes(raw, fmt), fmt)
    ok(`AES 密钥格式 ${fmt} -> ${b.length} 字节`, [16, 24, 32].includes(b.length), String(b.length))
  } catch (e) { ok(`AES 密钥格式 ${fmt}`, false, e.message) }
}
try { fitKeyBytes('cipher-aes', deriveKeyBytes('short', 'utf8'), 'utf8'); ok('AES 短密钥应报错', false) } catch (e) { ok('AES 短密钥应报错: ' + e.message, true) }
try { deriveIvBytes('cipher-aes', '0102', 'hex', 'CBC'); ok('IV 长度校验', false) } catch (e) { ok('IV 长度校验: ' + e.message, true) }
try { deriveIvBytes('cipher-aes', '', 'hex', 'CBC'); ok('CBC 缺 IV 应报错', false) } catch (e) { ok('CBC 缺 IV 应报错: ' + e.message, true) }
ok('ECB 不需要 IV', deriveIvBytes('cipher-aes', '', 'hex', 'ECB').length === 0)

log('\n== 错误密钥拒绝（PKCS#7 校验） ==')
const ctBad = encryptSymmetric({
  algoId: 'cipher-aes', keyBytes: deriveKeyBytes('0123456789abcdef', 'utf8'), ivBytes: iv, mode: 'CBC', padding: 'Pkcs7', plaintext: 'hello',
})
let badRejected = 0
for (let i = 0; i < 20; i++) {
  const wrongKey = deriveKeyBytes('fedcba98765432' + i.toString(16).padStart(2, '0'), 'utf8')
  try {
    decryptSymmetric({ algoId: 'cipher-aes', keyBytes: wrongKey, ivBytes: iv, mode: 'CBC', padding: 'Pkcs7', ciphertext: ctBad })
  } catch (e) { badRejected++ }
}
ok(`错误密钥被拒绝 ${badRejected}/20`, badRejected >= 19)

log('\n== 组件用到的辅助函数 ==')
ok('modesForAlgo(sm4)', modesForAlgo('cipher-sm4').map((m) => m.id).join(',') === 'CBC,ECB')
ok('modesForAlgo(rc4) 为空', modesForAlgo('cipher-rc4').length === 0)
ok('paddingsForAlgo(sm4) 仅 PKCS#7', paddingsForAlgo('cipher-sm4').map((p) => p.id).join(',') === 'Pkcs7')
ok('paddingsForAlgo(aes) 全量', paddingsForAlgo('cipher-aes').length === 6)
ok('CIPHER_MODES 数量', CIPHER_MODES.length === 6)
ok('SYMMETRIC_ALGOS 数量', Object.keys(SYMMETRIC_ALGOS).length === 8)

log('\n== ECDSA DER <-> RAW ==')
const raw32 = hexToBytes('00' + '11'.repeat(31) + 'ff' + '22'.repeat(31))
const der = rawSignatureToDer(raw32)
const back = derSignatureToRaw(new Uint8Array(der), 32)
ok('DER 往返', bytesToHex(back) === bytesToHex(raw32), bytesToHex(back).slice(0, 40))
ok('DER 头', der[0] === 0x30)

log(`\n通过 ${pass} / 失败 ${fail}`)
if (failures.length) log('\n失败明细:\n' + failures.map((f) => '  FAIL ' + f).join('\n'))
process.exitCode = fail ? 1 : 0
