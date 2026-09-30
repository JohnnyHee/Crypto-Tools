// 注意：Vite 默认只监听 ::1（IPv6 回环），所以必须用 [::1]；
// 写 127.0.0.1 会 ECONNREFUSED。
const base = process.env.BASE || 'http://[::1]:5180'
const urls = ['/', '/src/main.js', '/src/App.vue', '/src/components/KdfTool.vue']
for (const u of urls) {
  try {
    const r = await fetch(base + u)
    const t = await r.text()
    console.log(`${String(r.status).padEnd(4)} ${u.padEnd(32)} ${t.length} 字节`)
  } catch (e) {
    console.log(`ERR  ${u}  ${e.message}`)
  }
}
const html = await (await fetch(base + '/')).text()
console.log('\n标题:', /<title>(.*?)<\/title>/.exec(html)?.[1])
console.log('入口:', /<script[^>]*src="([^"]+)"/.exec(html)?.[1])
