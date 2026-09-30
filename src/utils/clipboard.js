/**
 * 剪贴板工具
 *
 * navigator.clipboard 只在安全上下文（https / localhost）可用，
 * 局域网 http://192.168.x.x 或 file:// 打开时会抛错——旧版代码把异常
 * 直接吞掉，用户点了"复制"完全没反应。这里补上 execCommand 回退。
 */
export async function copyText(text) {
  const value = String(text ?? '')
  if (!value) return false

  if (typeof navigator !== 'undefined' && navigator.clipboard && navigator.clipboard.writeText) {
    try {
      await navigator.clipboard.writeText(value)
      return true
    } catch (e) {
      /* 继续尝试回退方案 */
    }
  }

  if (typeof document === 'undefined') return false
  try {
    const ta = document.createElement('textarea')
    ta.value = value
    ta.setAttribute('readonly', '')
    ta.style.position = 'fixed'
    ta.style.top = '-2000px'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.select()
    ta.setSelectionRange(0, ta.value.length)
    const ok = document.execCommand('copy')
    document.body.removeChild(ta)
    return ok
  } catch (e) {
    return false
  }
}
