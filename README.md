# 🔐 Crypto Tools — 加解密工具集

<p align="center">
  <img src="https://img.shields.io/badge/Vue-3.4%2B-4FC08D?logo=vue.js" alt="Vue 3">
  <img src="https://img.shields.io/badge/Vite-5.2%2B-646CFF?logo=vite" alt="Vite">
  <img src="https://img.shields.io/badge/crypto--js-4.2%2B-blue" alt="crypto-js">
  <img src="https://img.shields.io/badge/SM--国密-✓-success" alt="国密支持">
  <img src="https://img.shields.io/badge/测试-225%20通过-success" alt="测试">
</p>

基于 **Vue 3 + Vite** 构建的纯浏览器端加解密工具集，共 **40 个工具**，覆盖摘要、对称加密、非对称加密、编码、密钥派生与随机生成，
并完整支持中国国密标准（SM2 / SM3 / SM4）。所有计算都在浏览器本地完成，**不向任何服务器发送数据**。

---

## 📋 目录

- [功能概览](#-功能概览)
- [快速开始](#-快速开始)
- [项目结构](#-项目结构)
- [技术栈](#-技术栈)
- [实现细节与坑](#-实现细节与坑)
- [测试](#-测试)
- [修复记录](#-修复记录)

---

## 🧰 功能概览

### #️⃣ 哈希 / 摘要 — 14 个

| 工具 | 说明 |
|------|------|
| `MD5` / `SHA-1` | 已不安全，仅用于校验与兼容旧系统 |
| `SHA-224` / `SHA-256` / `SHA-384` / `SHA-512` | SHA-2 家族 |
| `SHA3-224` / `SHA3-256` / `SHA3-384` / `SHA3-512` | NIST FIPS 202 标准 SHA-3 |
| `Keccak-256` | 以太坊使用的 Keccak（**与 NIST SHA3-256 不是同一个算法**） |
| `RIPEMD-160` | 比特币地址使用 |
| `SM3` 🇨🇳 | GB/T 32905-2016 国密哈希 |
| `CRC32` | 校验和，**不是**密码学哈希 |

每个摘要工具都带 **HMAC 模式**，支持 HMAC-MD5 / SHA1 / SHA224 / SHA256 / SHA384 / SHA512 / RIPEMD160 / **SM3**，密钥可用 UTF-8 / Hex / Base64 输入。

### 🔒 对称加密 — 8 个

| 工具 | 可选模式 | 分组 / 密钥 |
|------|----------|-------------|
| `AES` | CBC / ECB / CFB / OFB / CTR / CTR(Gladman) | 128 位分组，16 / 24 / 32 字节密钥 |
| `DES` | 同上 | 64 位分组，8 字节密钥 |
| `3DES` | 同上 | 64 位分组，8 / 16 / 24 字节密钥 |
| `Blowfish` | 同上 | 64 位分组，最长 56 字节密钥 |
| `RC4` / `RC4Drop` / `Rabbit` | 流密码 | Rabbit 支持可选 8 字节 IV |
| `SM4` 🇨🇳 | CBC / ECB | 128 位分组，16 字节密钥 |

- 填充方式：PKCS#7 / ZeroPadding / ANSI X9.23 / ISO 10126 / ISO/IEC 9797-1 / 不填充（SM4 底层仅支持 PKCS#7）
- 密钥格式：UTF-8 文本 / Hex / Base64 / MD5 派生 / SHA-256 派生
- **IV 真正可控**：本工具直接使用密钥字节（不走 OpenSSL 的 `EVP_BytesToKey` 口令派生），所以自定义 IV 生效，密文也不带 `Salted__` 前缀，并会给出对应的 `openssl enc -K <hex> -iv <hex>` 命令
- 密文输出支持 Base64 / Hex，解密支持非法 UTF-8 时回退显示 Hex

### 🔑 非对称加密 — 4 个

| 工具 | 功能 |
|------|------|
| `RSA` | 512 / 1024 / 2048 / 4096 位密钥生成（WebCrypto，位数精确）、PKCS#1 v1.5 与 **RSA-OAEP/SHA-256** 加解密、SHA-1/256/512 签名验签 |
| `ECDSA` | P-256 / P-384 / P-521，SHA-256/384/512，签名格式 raw(Base64) / der(Base64) / rawhex(Hex) |
| `Ed25519` | 密钥生成、签名（固定 64 字节）、验签 |
| `SM2` 🇨🇳 | 密钥生成、加解密（C1C3C2 / C1C2C3）、签名验签（DER / RAW） |

密钥兼容性做了归一化：PKCS#8 ↔ PKCS#1、SPKI ↔ PKCS#1 公钥、裸 Base64、CRLF 换行、缺失 PEM 头尾都能识别（靠 DER 结构嗅探）。

### 🔤 编码 / 解码 — 8 个

`Base64`（可选 76 字符折行）、`Base64URL`、`Hex`（可选大写）、`URL 编码`（encodeURI / encodeURIComponent）、`HTML 实体`、`Unicode 转义`（含 `\u{}`、`\xNN` 与 emoji 代理对）、`二进制位串`、`JWT 解析`（解开头部/载荷 + 时间字段可读化）。

### 🧬 密钥派生 (KDF) — 3 个

| 工具 | 说明 |
|------|------|
| `PBKDF2` | RFC 8018，MD5 / SHA-1 / SHA-256 / SHA-512，迭代次数可达 200 万 |
| `HKDF` | RFC 5869，Extract + Expand，可查看中间量 PRK |
| `摘要派生` | `digest(password ‖ salt ‖ counter)`，仅用于理解原理 |

### 🎲 随机生成 — 3 个

`随机字节`（1–1024 字节，Hex / Base64 / Base64URL / 可打印字符）、`随机密码`（可选字符集、排除易混淆字符 I l 1 O 0 o、每类至少一个，显示信息熵与强度评估）、`UUID / ULID`（UUID v4、UUID v7、ULID、NanoID、短 ID）。

---

## 🚀 快速开始

```bash
npm install
npm run dev        # 开发服务器 → http://localhost:5173
npm run build      # 生产构建 → dist/
npm run preview    # 预览生产构建
npm test           # 运行回归测试（225 项断言）
```

环境要求：Node.js 18+。

---

## 📁 项目结构

```
crypto-tools/
├── index.html
├── package.json
├── vite.config.js
├── tests/
│   ├── loader.mjs                  # Node ESM 解析钩子（补全无扩展名导入）
│   ├── register.mjs                # 注册上面的钩子
│   ├── symmetric.test.mjs          # 摘要 / HMAC / 对称加密回归（107 项）
│   └── asymmetric.test.mjs         # PEM / RSA / ECDSA / Ed25519 / SM2 回归（118 项）
└── src/
    ├── main.js                     # 入口，导入全局样式
    ├── App.vue                     # 侧边栏导航（含搜索）+ 工具路由
    ├── styles/main.css             # 设计令牌与全部全局样式
    ├── components/
    │   ├── HashTool.vue            # 摘要 + HMAC
    │   ├── SymmetricCipher.vue     # 对称加密 / 解密
    │   ├── AsymmetricCipher.vue    # RSA / ECDSA / Ed25519 / SM2
    │   ├── EncodeDecode.vue        # 8 种编解码
    │   ├── KdfTool.vue             # PBKDF2 / HKDF / 摘要派生
    │   └── RandomTool.vue          # 随机字节 / 密码 / UUID
    └── utils/                      # 纯函数实现（可在 Node 下直接单测）
        ├── bytes.js                # 字节 / Hex / Base64 / PEM / DER
        ├── hash.js                 # 摘要与 HMAC
        ├── cipher.js               # 对称加密
        ├── asymmetric.js           # 非对称加密
        ├── encode.js               # 编解码
        ├── kdf.js                  # 密钥派生
        ├── random.js               # 随机数与密码
        └── clipboard.js            # 复制（含 execCommand 回退）
```

设计上把**所有加解密逻辑放在 `src/utils/` 的纯函数里**，Vue 组件只负责交互状态。这样算法部分可以脱离浏览器在 Node 下直接跑回归测试。

---

## 🛠️ 技术栈

| 技术 | 版本 | 用途 |
|------|------|------|
| **Vue 3** | ^3.4.21 | Composition API + `<script setup>` |
| **Vite** | ^5.2.0 | 构建工具 |
| **crypto-js** | ^4.2.0 | 摘要、HMAC、对称加密 |
| **jsencrypt** | ^3.5.4 | RSA PKCS#1 v1.5 与签名 |
| **sm-crypto** | ^0.4.0 | 国密 SM2 / SM3 / SM4 |
| **WebCrypto** | 浏览器原生 | RSA 密钥生成、RSA-OAEP、ECDSA、Ed25519、随机数 |

---

## 🔍 实现细节与坑

这些是开发中实测确认过的行为，直接决定了实现方式：

1. **crypto-js 的 `SHA3` 其实是 Keccak**。`CryptoJS.SHA3("abc")` 等于 Keccak-512，`{outputLength:256}` 等于 Keccak-256，都**不是** NIST FIPS 202 的 SHA-3。
   本项目内部实现了真正的 SHA-3（`src/utils/hash.js` 的 `sha3()`），同时把 Keccak-256 单独列成一个工具（以太坊用它）。
2. **口令式加密会忽略你传入的 IV**。`CryptoJS.AES.encrypt(text, "字符串口令", {iv})` 内部走 `PasswordBasedCipher`，`cfg.iv` 会被 OpenSSL KDF 派生出的 IV **覆盖**，而且每次随机加盐，输出带 `Salted__` 前缀、同一明文每次密文都不同。
   所以只要用户想控制 IV，就必须先把密钥转成 `WordArray` 再传（走 `SerializableCipher`），本项目就是这么做的。
3. **解密时不能用 crypto-js 的自动去填充再手工校验**。`Cipher.finalize()` 已经按 padding 配置做过一次去填充，如果再校验一次必然误判为"填充错误"。
   本项目在解密路径上统一强制 `CryptoJS.pad.NoPadding`，自己实现 `unpad()` 并按所选填充严格校验。
4. **`sm-crypto` 的 `doSignature(msg, key, {der:true})` 返回的是 Hex 字符串**，不是字节数组。旧代码对它逐字节 `toString(16)` 又编码了一遍，导致签名永远验不过。
5. **`sm-crypto` 的 SM2 密文不带 `04` 前缀**（`doEncrypt` 内部已 `substr` 掉），而 `doDecrypt` 自己会补 `04`。所以对外输出统一加 `04`（标准互换格式），解密时两种形态都尝试。
6. **`sm-crypto` 的 SM4 默认是 ECB**，只有显式传 `mode:'cbc'` 才校验 IV 长度；密钥必须正好 16 字节。填充只支持 PKCS#7。
7. **`sm-crypto` 是纯 CommonJS**（`main: src/index.js`，无 `exports` 字段），靠 Vite 的依赖预打包做互操作；其 `lib/index.js` 里有无扩展名相对导入，所以 Node 下跑测试需要 `tests/register.mjs` 这个解析钩子。
8. **`jsencrypt` 生成的 RSA 密钥位数会少 1 bit**（请求 1024 位时 `key.n.bitLength() === 1023`），因此密钥生成优先走 WebCrypto，jsencrypt 只作回落。
9. **`jsencrypt` 的私钥是 PKCS#1**（`BEGIN RSA PRIVATE KEY`），WebCrypto `importKey('pkcs8')` 会报 `wrong tag`，必须先转换成 PKCS#8。
10. **`CryptoJS.enc.Base64.parse('!!!!')` 不报错**，会静默返回空字节；`CryptoJS.enc.Utf8.stringify` 遇到非法 UTF-8 会抛 `Malformed UTF-8 data`。所以 Base64 / Hex 输入都要自己先做合法性预检。
11. **`btoa(String.fromCharCode(...new Uint8Array(n)))` 在 n 较大时会爆栈**（`Maximum call stack size exceeded`），字节转 Base64 必须分块。
12. **Rabbit 必须用 16 字节密钥**，长度不对会产出乱码并在解密时报 `Malformed UTF-8 data`。
13. 随机密码洗牌用的是 **32 位拒绝采样**，不是 `value % max`，避免模偏差；随机数统一走 `crypto.getRandomValues`，不用 `Math.random()`。

---

## 🧪 测试

```bash
npm test
```

- `tests/symmetric.test.mjs` — **107 项**：18 条摘要官方向量、8 种 HMAC、NIST SP 800-38A 的 AES-128-CBC / AES-128-ECB / AES-256-CBC / AES-256-CTR 官方向量、GB/T 32907-2016 的 SM4 官方向量、8 种算法 × 全部模式 × 6 种填充的往返、密钥/IV 长度校验、错误密钥拒绝、ECDSA DER↔RAW 往返。
- `tests/asymmetric.test.mjs` — **118 项**：PEM 归一化、RSA 各种密钥形态（PKCS#1/PKCS#8/裸 Base64/CRLF/无头尾）、RSA 位数精度、明文长度上限、OAEP、ECDSA 三种曲线 × 三种签名格式（含篡改与换密钥拒绝）、Ed25519、SM2（两种 C1 顺序、两种签名编码、换密钥拒绝）、以及 KDF / 编码 / 随机的冒烟测试。

合计 **225 项断言，全部通过**。

---

## 🩹 修复记录

上一版（DeepSeek V4 Flash 预览版）存在以下问题，均已修复：

| # | 问题 | 后果 |
|---|------|------|
| 1 | `AsymmetricCipher.vue` 声明了 `props.tool` 却**完全没使用**，内部用默认值 `'rsa'` | 侧边栏点 ECDSA / SM2 永远只显示 RSA |
| 2 | 切换算法时 `activeOp` 不重置 | 从 RSA 切到 ECDSA 后仍停在"加密"，而 ECDSA 没有加密操作，`switch` 无匹配分支，**界面静默什么都不发生** |
| 3 | SM2 签名把 `{der:true}` 返回的 Hex 字符串当字节数组又转了一次十六进制 | **签名永远验不过** |
| 4 | 对称加密传入字符串口令 + 自定义 IV | crypto-js 走口令派生，**IV 被忽略**，界面显示的"使用的 IV"是假的，且同一明文每次密文都不同 |
| 5 | 对称加密切换算法时不清空/重置模式、填充、密钥 | 选中 SM4 却留着 AES 的模式，点加密直接抛错 |
| 6 | SHA3 实际算的是 Keccak | 拿到的摘要与任何标准工具都对不上 |
| 7 | 组件内用 `watch` 触发计算，解码失败时只设 `error` 不清理结果 | 上一次的成功结果会残留，看起来像"成功了" |
| 8 | 编码解码组件末尾有 `if (!output.value && output.value !== '')` | 永远为 false 的死代码 |
| 9 | 复制只用 `navigator.clipboard`，`catch` 为空 | 在 http（非 https/localhost）下点复制没有任何反应，也没有提示 |
| 10 | 解码路径没有输入校验 | `CryptoJS.enc.Base64.parse('!!!!')` 静默返回脏字节，用户以为解码成功了 |
| 11 | `main.css` 写好了但 `main.js` 从未导入 | 新样式完全没生效 |
| 12 | RSA 密钥生成用 jsencrypt | 请求 1024 位实际得到 1023 位，明文长度上限算成小数 |

除此之外还修掉了若干内部问题：随机整数的 256 上限导致长密码洗牌崩溃、`pemToBytes()` 调用参数写反、jsencrypt 的 PKCS#1 私钥直接喂给 WebCrypto 报 `wrong tag`、SM2 公钥 130/128 位形态不一致、ECDSA DER 转 RAW 时曲线长度传成小数等。

---

## 📄 许可证

本项目仅供学习和研究使用。
