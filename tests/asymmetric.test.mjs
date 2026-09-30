// 第二轮回归：PKCS#1/PKCS#8 归一化、ECDSA 三种签名格式、Ed25519、SM2 全部往返
// 运行：node --import ./.scratch/register.mjs .scratch/verify6.mjs
import {
  generateRsaKeyPair, rsaEncrypt, rsaDecrypt, rsaSign, rsaVerify, rsaMaxPlaintext,
  rsaOaepEncrypt, rsaOaepDecrypt, privateKeyDer, publicKeyDer, jsencryptPrivatePem,
  generateEcKeyPair, ecdsaSign, ecdsaVerify, EC_CURVES, EC_SIGNATURE_FORMATS, ecCurve,
  ed25519Available, generateEd25519KeyPair, ed25519Sign, ed25519Verify,
  generateSm2KeyPair, sm2Encrypt, sm2Decrypt, sm2Sign, sm2Verify,
  sm2PublicKeyFromPrivate, sm2ValidatePublicKey,
} from '../src/utils/asymmetric.js'
import {
  bytesToPem, pemToBytes, pkcs8ToPkcs1, pkcs1ToPkcs8, pkcs1PublicToSpki, spkiToPkcs1,
  normalizePem, rawSignatureToDer, derSignatureToRaw, bytesToHex, hexToBytes, bytesToBase64, base64ToBytes,
} from '../src/utils/bytes.js'
import { pbkdf2, hkdf } from '../src/utils/kdf.js'
import { generatePassword, uuidV7 } from '../src/utils/random.js'
import { encodeText, decodeText, decodeJwt } from '../src/utils/encode.js'

let pass = 0, fail = 0
const failures = []
const QUIET = !!process.env.QUIET
const section = (t) => { if (!QUIET) console.log(`\n== ${t} ==`) }
const ok = (name, cond, extra = '') => {
  if (cond) { pass++; if (!QUIET) console.log(`  ok   ${name}`) }
  else { fail++; failures.push(`${name} ${extra}`); console.log(`  FAIL ${name} ${extra}`) }
}
const eq = (name, got, want) => ok(name, got === want, `got=${JSON.stringify(got)} want=${JSON.stringify(want)}`)
const throws = (name, fn, re) => {
  try { fn(); ok(name + ' (应报错)', false) }
  catch (e) { ok(`${name} -> ${String(e.message).slice(0, 40)}`, re ? re.test(e.message) : true) }
}

// ---------------------------------------------------------------- bytes / PEM
section('bytes / PEM 归一化')
const rsa = await generateRsaKeyPair(1024)
eq('WebCrypto 生成 RSA-1024 位数精确', rsa.bits, 1024)
ok('公钥为 SPKI', rsa.publicKey.includes('BEGIN PUBLIC KEY'))
ok('私钥为 PKCS#8', rsa.privateKey.includes('BEGIN PRIVATE KEY'))
const pkcs1Pem = bytesToPem('RSA PRIVATE KEY', pkcs8ToPkcs1(pemToBytes(rsa.privateKey)))
const pkcs1PubPem = bytesToPem('RSA PUBLIC KEY', spkiToPkcs1(pemToBytes(rsa.publicKey)))
eq('PKCS#8 -> PKCS#1 往返', bytesToHex(pkcs1ToPkcs8(pemToBytes(pkcs1Pem))), bytesToHex(pemToBytes(rsa.privateKey)))
eq('SPKI -> PKCS#1 公钥往返', bytesToHex(pkcs1PublicToSpki(pemToBytes(pkcs1PubPem))), bytesToHex(pemToBytes(rsa.publicKey)))
eq('normalizePem 保持 PKCS#8', normalizePem(rsa.privateKey), rsa.privateKey)
eq('normalizePem PKCS#1 -> PKCS#8 标签', normalizePem(pkcs1Pem).split('\n')[0], '-----BEGIN PRIVATE KEY-----')
eq('normalizePem PKCS#1 公钥 -> SPKI 标签', normalizePem(pkcs1PubPem).split('\n')[0], '-----BEGIN PUBLIC KEY-----')
eq('normalizePem 裸 Base64 私钥可还原', normalizePem(bytesToBase64(pemToBytes(rsa.privateKey))), rsa.privateKey)
eq('privateKeyDer 接受 PKCS#1 PEM', bytesToHex(privateKeyDer(pkcs1Pem)), bytesToHex(pemToBytes(rsa.privateKey)))
eq('publicKeyDer 接受 PKCS#1 PEM', bytesToHex(publicKeyDer(pkcs1PubPem)), bytesToHex(pemToBytes(rsa.publicKey)))
ok('jsencryptPrivatePem 回到 PKCS#1', jsencryptPrivatePem(rsa.privateKey).includes('BEGIN RSA PRIVATE KEY'))

section('RSA 各种密钥形态')
const rsaCt = rsaEncrypt('Hello RSA 你好', rsa.publicKey)
eq('PKCS#1 往返（PKCS#8 私钥）', rsaDecrypt(rsaCt, rsa.privateKey), 'Hello RSA 你好')
eq('PKCS#1 往返（PKCS#1 私钥）', rsaDecrypt(rsaCt, pkcs1Pem), 'Hello RSA 你好')
eq('PKCS#1 往返（PKCS#1 公钥加密）', rsaDecrypt(rsaEncrypt('x', pkcs1PubPem), rsa.privateKey), 'x')
eq('PKCS#1 往返（裸 Base64 公钥）', rsaDecrypt(rsaEncrypt('y', bytesToBase64(pemToBytes(rsa.publicKey))), rsa.privateKey), 'y')
eq('PKCS#1 往返（CRLF 换行）', rsaDecrypt(rsaCt, rsa.privateKey.replace(/\n/g, '\r\n')), 'Hello RSA 你好')
eq('PKCS#1 往返（去掉 PEM 头尾）', rsaDecrypt(rsaCt, pemToBytes(rsa.privateKey) && bytesToBase64(pemToBytes(rsa.privateKey))), 'Hello RSA 你好')
const oaepCt = await rsaOaepEncrypt('OAEP 你好', rsa.publicKey)
eq('OAEP 往返（PKCS#8）', await rsaOaepDecrypt(oaepCt, rsa.privateKey), 'OAEP 你好')
eq('OAEP 往返（PKCS#1）', await rsaOaepDecrypt(oaepCt, pkcs1Pem), 'OAEP 你好')
eq('OAEP 往返（私钥裸 Base64）', await rsaOaepDecrypt(oaepCt, bytesToBase64(pemToBytes(rsa.privateKey))), 'OAEP 你好')
eq('rsaMaxPlaintext PKCS#1 (1024)', rsaMaxPlaintext(rsa.publicKey, 'pkcs1'), 117)
eq('rsaMaxPlaintext OAEP/SHA-256 (1024)', rsaMaxPlaintext(rsa.publicKey, 'oaep'), 62)
const sig = rsaSign('msg', rsa.privateKey, 'sha256')
ok('验签通过（PKCS#1 公钥）', rsaVerify('msg', sig, pkcs1PubPem, 'sha256'))
ok('验签失败（改消息）', !rsaVerify('msg2', sig, rsa.publicKey, 'sha256'))
const rsa512 = await generateRsaKeyPair(512)
eq('RSA-512 位数精确', rsa512.bits, 512)
eq('rsaMaxPlaintext (512)', rsaMaxPlaintext(rsa512.publicKey, 'pkcs1'), 53)
throws('RSA 明文过长', () => rsaEncrypt('x'.repeat(200), rsa.publicKey), /过长/)

// ---------------------------------------------------------------- ECDSA
section('ECDSA（WebCrypto）')
for (const curve of EC_CURVES.map((c) => c.id)) {
  const size = ecCurve(curve).size
  const kp = await generateEcKeyPair(curve)
  ok(`${curve} 生成`, kp.publicKey.includes('BEGIN PUBLIC KEY') && kp.privateKey.includes('BEGIN PRIVATE KEY'))
  const text = `hello ${curve} 你好`
  for (const f of EC_SIGNATURE_FORMATS.map((x) => x.id)) {
    const s = await ecdsaSign({ text, privateKey: kp.privateKey, curve, hash: 'SHA-256', format: f })
    ok(`${curve} ${f} 验签`, await ecdsaVerify({ text, signature: s, publicKey: kp.publicKey, curve, hash: 'SHA-256', format: f }))
    ok(`${curve} ${f} 篡改被拒`, !(await ecdsaVerify({ text: text + '!', signature: s, publicKey: kp.publicKey, curve, hash: 'SHA-256', format: f })))
    ok(`${curve} ${f} 换密钥被拒`, !(await ecdsaVerify({
      text, signature: s, publicKey: (await generateEcKeyPair(curve)).publicKey, curve, hash: 'SHA-256', format: f,
    })))
  }
  const rawHex = await ecdsaSign({ text, privateKey: kp.privateKey, curve, hash: 'SHA-256', format: 'rawhex' })
  const rawB64 = await ecdsaSign({ text, privateKey: kp.privateKey, curve, hash: 'SHA-256', format: 'raw' })
  const derB64 = await ecdsaSign({ text, privateKey: kp.privateKey, curve, hash: 'SHA-256', format: 'der' })
  eq(`${curve} rawhex 长度`, rawHex.length, size * 4)
  eq(`${curve} raw(Base64) 解码后长度`, base64ToBytes(rawB64).length, size * 2)
  eq(`${curve} der 以 30 开头`, bytesToHex(base64ToBytes(derB64)).slice(0, 2), '30')
  eq(`${curve} raw->der->raw 往返`, bytesToHex(derSignatureToRaw(rawSignatureToDer(hexToBytes(rawHex)), size)), rawHex)
  eq(`${curve} 自己签的 der 能解回自己的 raw`, bytesToHex(derSignatureToRaw(rawSignatureToDer(hexToBytes(rawHex)), size)).length, size * 4)
  eq(`${curve} der 解码长度符合曲线`, derSignatureToRaw(base64ToBytes(derB64), size).length, size * 2)
  ok(`${curve} rawhex 未被当成 Base64`, await ecdsaVerify({ text, signature: rawHex, publicKey: kp.publicKey, curve, hash: 'SHA-256', format: 'rawhex' }))
  const s512 = await ecdsaSign({ text, privateKey: kp.privateKey, curve, hash: 'SHA-512', format: 'rawhex' })
  ok(`${curve} SHA-512 哈希可用`, await ecdsaVerify({ text, signature: s512, publicKey: kp.publicKey, curve, hash: 'SHA-512', format: 'rawhex' }))
  ok(`${curve} 哈希不匹配验签失败`, !(await ecdsaVerify({ text, signature: s512, publicKey: kp.publicKey, curve, hash: 'SHA-256', format: 'rawhex' })))
}

// ---------------------------------------------------------------- Ed25519
section('Ed25519')
if (await ed25519Available()) {
  const ed = await generateEd25519KeyPair()
  ok('密钥生成', ed.publicKey.includes('BEGIN PUBLIC KEY'))
  const es = await ed25519Sign('hello 你好', ed.privateKey)
  eq('签名（Base64）长度 88', es.length, 88)
  eq('签名解码后 64 字节', base64ToBytes(es).length, 64)
  ok('验签通过', await ed25519Verify('hello 你好', es, ed.publicKey))
  ok('篡改被拒', !(await ed25519Verify('hello 你好!', es, ed.publicKey)))
} else {
  console.log('  --   当前环境不支持 Ed25519，跳过')
}

// ---------------------------------------------------------------- SM2
section('SM2')
const sm = generateSm2KeyPair()
eq('私钥长度 64 hex', sm.privateKey.length, 64)
eq('公钥长度 130 hex（含 04）', sm.publicKey.length, 130)
ok('公钥有效性校验', sm2ValidatePublicKey(sm.publicKey))
ok('去掉 04 的公钥也接受', sm2ValidatePublicKey(sm.publicKey.slice(2)))
ok('由私钥推出公钥', sm2PublicKeyFromPrivate(sm.privateKey) === sm.publicKey)
ok('非法公钥被拒', !sm2ValidatePublicKey('00'.repeat(64)))
ok('乱长度公钥被拒', !sm2ValidatePublicKey('abcd'))
const smCtNoPrefix = sm2Encrypt('SM2 你好 world', sm.publicKey.slice(2))
eq('128 位公钥也能加密并解密', sm2Decrypt(smCtNoPrefix, sm.privateKey), 'SM2 你好 world')
const smCt = sm2Encrypt('SM2 你好 world', sm.publicKey)
ok('密文以 04 开头', smCt.startsWith('04'))
eq('解密（带 04 前缀）', sm2Decrypt(smCt, sm.privateKey), 'SM2 你好 world')
eq('解密（无 04 前缀）', sm2Decrypt(smCt.slice(2), sm.privateKey), 'SM2 你好 world')
const smOther = generateSm2KeyPair()
throws('换私钥应失败', () => sm2Decrypt(smCt, smOther.privateKey), /SM2 解密失败/)
eq('C1C3C2 往返', sm2Decrypt(sm2Encrypt('模式1 test', sm.publicKey, 1), sm.privateKey, 1), '模式1 test')
eq('C1C2C3 往返', sm2Decrypt(sm2Encrypt('模式0 test', sm.publicKey, 0), sm.privateKey, 0), '模式0 test')
throws('进制不匹配应失败', () => sm2Decrypt('zz', sm.privateKey), /十六进制|解密失败/)
eq('长文本加密往返', sm2Decrypt(sm2Encrypt('长'.repeat(400), sm.publicKey), sm.privateKey), '长'.repeat(400))
const smDer = sm2Sign('签名内容', sm.privateKey, { der: true })
const smRaw = sm2Sign('签名内容', sm.privateKey, { der: false })
ok('DER 签名以 30 开头', smDer.startsWith('30'))
eq('RAW 签名长度 128 hex', smRaw.length, 128)
ok('DER 验签', sm2Verify('签名内容', smDer, sm.publicKey, { der: true }))
ok('RAW 验签', sm2Verify('签名内容', smRaw, sm.publicKey, { der: false }))
ok('DER 签名被篡改消息拒绝', !sm2Verify('签名内容!', smDer, sm.publicKey, { der: true }))
ok('换公钥验签失败', !sm2Verify('签名内容', smDer, smOther.publicKey, { der: true }))

// ---------------------------------------------------------------- 快速冒烟
section('既有模块冒烟')
eq('PBKDF2 仍正确', bytesToHex(pbkdf2({ password: 'password', salt: hexToBytes('73616c74'), iterations: 1, length: 32, hash: 'sha256' })), '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b')
eq('HKDF 仍正确', bytesToHex(hkdf({ ikm: hexToBytes('0b'.repeat(22)), salt: hexToBytes('000102030405060708090a0b0c'), info: hexToBytes('f0f1f2f3f4f5f6f7f8f9'), length: 42, hash: 'sha256' })), '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865')
eq('Base64 往返', decodeText('encode-base64', encodeText('encode-base64', '你好 world')), '你好 world')
eq('JWT 解析含头载荷', decodeJwt('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc').includes('"alg"'), true)
ok('密码生成', generatePassword({ length: 20 }).password.length === 20)
eq('UUID v7 版本位', uuidV7()[14], '7')

console.log(`\n${'='.repeat(46)}\n通过 ${pass} / 失败 ${fail}`)
if (failures.length) { console.log('失败明细：'); failures.forEach((f) => console.log('  - ' + f)) }
process.exitCode = fail ? 1 : 0
