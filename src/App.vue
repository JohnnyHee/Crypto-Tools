<template>
  <div class="app-layout">
    <aside class="sidebar" :class="{ collapsed: sidebarCollapsed }">
      <div class="sidebar-header">
        <h1 class="logo">
          <span class="logo-icon">🔐</span>
          <span v-show="!sidebarCollapsed">Crypto Tools</span>
        </h1>
        <button class="toggle-btn" @click="sidebarCollapsed = !sidebarCollapsed">
          {{ sidebarCollapsed ? '☰' : '✕' }}
        </button>
      </div>

      <div class="sidebar-search" v-show="!sidebarCollapsed">
        <input v-model="search" type="text" placeholder="搜索工具…" />
      </div>

      <nav class="sidebar-nav">
        <div v-for="group in filteredGroups" :key="group.label" class="nav-group">
          <div class="nav-group-label" v-show="!sidebarCollapsed">{{ group.label }}</div>
          <a
            v-for="tool in group.tools"
            :key="tool.id"
            class="nav-item"
            :class="{ active: activeTool === tool.id }"
            @click.prevent="activeTool = tool.id"
            :title="tool.name"
          >
            <span class="nav-icon">{{ tool.icon }}</span>
            <span v-show="!sidebarCollapsed" class="nav-text">{{ tool.name }}</span>
          </a>
        </div>
        <div v-if="!filteredGroups.length" class="nav-empty" v-show="!sidebarCollapsed">
          没有匹配的工具
        </div>
      </nav>

      <div class="sidebar-footer" v-show="!sidebarCollapsed">
        {{ totalTools }} 个工具 · 全部在浏览器本地运行
      </div>
    </aside>

    <main class="main-content">
      <div class="tool-container">
        <HashTool v-if="activeTool.startsWith('hash-')" :tool="activeTool" />
        <SymmetricCipher v-else-if="activeTool.startsWith('cipher-')" :tool="activeTool" />
        <AsymmetricCipher v-else-if="ASYMMETRIC_IDS.includes(activeTool)" :tool="activeTool" />
        <EncodeDecode v-else-if="activeTool.startsWith('encode-')" :tool="activeTool" />
        <KdfTool v-else-if="activeTool.startsWith('kdf-')" :tool="activeTool" />
        <RandomTool v-else-if="activeTool.startsWith('random-')" :tool="activeTool" />
      </div>
    </main>
  </div>
</template>

<script setup>
import { computed, ref } from 'vue'
import HashTool from './components/HashTool.vue'
import SymmetricCipher from './components/SymmetricCipher.vue'
import AsymmetricCipher from './components/AsymmetricCipher.vue'
import EncodeDecode from './components/EncodeDecode.vue'
import KdfTool from './components/KdfTool.vue'
import RandomTool from './components/RandomTool.vue'

const sidebarCollapsed = ref(false)
const activeTool = ref('hash-md5')
const search = ref('')

const ASYMMETRIC_IDS = ['rsa', 'ecdsa', 'ed25519', 'sm2']

const toolGroups = [
  {
    label: '哈希 / 摘要',
    tools: [
      { id: 'hash-md5', name: 'MD5', icon: 'MD5' },
      { id: 'hash-sha1', name: 'SHA-1', icon: 'S1' },
      { id: 'hash-sha256', name: 'SHA-256', icon: 'S2' },
      { id: 'hash-sha224', name: 'SHA-224', icon: 'S2' },
      { id: 'hash-sha384', name: 'SHA-384', icon: 'S3' },
      { id: 'hash-sha512', name: 'SHA-512', icon: 'S5' },
      { id: 'hash-sha3-224', name: 'SHA3-224', icon: '3a' },
      { id: 'hash-sha3-256', name: 'SHA3-256', icon: '3b' },
      { id: 'hash-sha3-384', name: 'SHA3-384', icon: '3c' },
      { id: 'hash-sha3-512', name: 'SHA3-512', icon: '3d' },
      { id: 'hash-keccak256', name: 'Keccak-256', icon: 'Kc' },
      { id: 'hash-ripemd160', name: 'RIPEMD-160', icon: 'RP' },
      { id: 'hash-sm3', name: 'SM3 (国密)', icon: 'S3' },
      { id: 'hash-crc32', name: 'CRC32', icon: 'C3' },
    ],
  },
  {
    label: '对称加密',
    tools: [
      { id: 'cipher-aes', name: 'AES', icon: 'AE' },
      { id: 'cipher-des', name: 'DES', icon: 'DE' },
      { id: 'cipher-tripledes', name: '3DES', icon: '3D' },
      { id: 'cipher-blowfish', name: 'Blowfish', icon: 'BF' },
      { id: 'cipher-rc4', name: 'RC4', icon: 'RC' },
      { id: 'cipher-rc4drop', name: 'RC4Drop', icon: 'RD' },
      { id: 'cipher-rabbit', name: 'Rabbit', icon: 'RB' },
      { id: 'cipher-sm4', name: 'SM4 (国密)', icon: 'S4' },
    ],
  },
  {
    label: '非对称加密',
    tools: [
      { id: 'rsa', name: 'RSA', icon: 'RK' },
      { id: 'ecdsa', name: 'ECDSA', icon: 'EC' },
      { id: 'ed25519', name: 'Ed25519', icon: 'ED' },
      { id: 'sm2', name: 'SM2 (国密)', icon: 'S2' },
    ],
  },
  {
    label: '编码 / 解码',
    tools: [
      { id: 'encode-base64', name: 'Base64', icon: 'B6' },
      { id: 'encode-base64url', name: 'Base64URL', icon: 'BU' },
      { id: 'encode-hex', name: 'Hex', icon: 'Hx' },
      { id: 'encode-url', name: 'URL 编码', icon: 'UR' },
      { id: 'encode-html', name: 'HTML 实体', icon: 'HT' },
      { id: 'encode-unicode', name: 'Unicode 转义', icon: 'Un' },
      { id: 'encode-binary', name: '二进制位串', icon: '01' },
      { id: 'encode-jwt', name: 'JWT 解析', icon: 'JW' },
    ],
  },
  {
    label: '密钥派生 (KDF)',
    tools: [
      { id: 'kdf-pbkdf2', name: 'PBKDF2', icon: 'PB' },
      { id: 'kdf-hkdf', name: 'HKDF', icon: 'HK' },
      { id: 'kdf-digest', name: '摘要派生', icon: 'DG' },
    ],
  },
  {
    label: '随机生成',
    tools: [
      { id: 'random-bytes', name: '随机字节', icon: 'RB' },
      { id: 'random-password', name: '随机密码', icon: 'PW' },
      { id: 'random-uuid', name: 'UUID / ULID', icon: 'ID' },
    ],
  },
]

const totalTools = toolGroups.reduce((n, g) => n + g.tools.length, 0)

const filteredGroups = computed(() => {
  const q = search.value.trim().toLowerCase()
  if (!q) return toolGroups
  return toolGroups
    .map((g) => ({
      label: g.label,
      tools: g.tools.filter(
        (t) =>
          t.name.toLowerCase().includes(q) ||
          t.id.toLowerCase().includes(q) ||
          g.label.toLowerCase().includes(q)
      ),
    }))
    .filter((g) => g.tools.length)
})
</script>
