// 口令输入：掩码 + 二次确认。
//
// 三条不可妥协的规矩（docs/48）：
//  1. **一律 type="password"**，不提供"显示口令"开关。掩码只影响显示层：
//     value / onChange 拿到的始终是真实字符，不做任何 transform。
//  2. **粘贴、删除、输入法上屏都必须走同一条路径**。只要用原生 input + type=password，
//     浏览器就保证这几种操作都被掩码；反过来，任何"自己画掩码"的实现都会在
//     粘贴和退格时露馅。所以这里不拦 onPaste、不拦 onKeyDown。
//  3. **移动端关掉自动纠正**：autoCorrect/autoCapitalize 会把首字母改成大写、
//     把拼写"纠正"掉，用户看不到（掩码），却导致登录失败。这是最容易漏的一处。
//
// 二次确认只做客户端校验，请求体仍然只提交 password 一个字段——
// 服务端不需要知道 confirm，也不应该因为多一个字段而改变校验逻辑。

import type { ReactNode } from 'react'

/** 口令长度下限。与服务端 internal/password.MinLength 必须一致。 */
export const MIN_PASSWORD = 8

/**
 * 计算两次输入是否可提交。返回 null 表示通过，否则返回可直接展示的提示。
 *
 * 用展开运算符数"字符"而不是 .length：后者数的是 UTF-16 码元，
 * emoji 会被算成 2 位，与服务端 utf8 字符数口径不一致。
 */
export function passwordPairError(
  pw: string,
  confirm: string,
  min: number = MIN_PASSWORD,
): string | null {
  if (!pw) return '请填写口令'
  if ([...pw].length < min) return `口令至少 ${min} 位`
  if (!confirm) return '请再次输入口令以确认'
  if (pw !== confirm) return '两次输入的口令不一致，请重新输入'
  return null
}

type Props = {
  /** 用于生成 id/htmlFor，同一页面内需唯一 */
  id: string
  label?: string
  confirmLabel?: string
  value: string
  onChange: (v: string) => void
  confirm: string
  onConfirm: (v: string) => void
  /** current-password 用于"旧口令"，new-password 用于设置新口令 */
  autoComplete?: 'new-password' | 'current-password' | 'off'
  minLength?: number
  disabled?: boolean
  hint?: ReactNode
  autoFocus?: boolean
  /** 提交过一次之后置 true：把"没填/太短"也显性提示出来 */
  submitted?: boolean
}

export function PasswordPair({
  id, label = '口令', confirmLabel = '确认口令',
  value, onChange, confirm, onConfirm,
  autoComplete = 'new-password', minLength = MIN_PASSWORD,
  disabled, hint, autoFocus, submitted,
}: Props) {
  const mismatch = !!(confirm && value !== confirm)
  const error = passwordPairError(value, confirm, minLength)
  // 不一致时立刻提示（用户正在逐字比对）；"没填/太短"等到提交后再提示，
  // 否则刚打开弹窗就一片红。
  const showNow = mismatch || (submitted && !!error)

  return (
    <>
      <div className="field">
        <label htmlFor={`${id}-pw`}>{label}</label>
        <input
          id={`${id}-pw`}
          type="password"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          autoComplete={autoComplete}
          minLength={minLength}
          required
          disabled={disabled}
          autoFocus={autoFocus}
          spellCheck={false}
          autoCorrect="off"
          autoCapitalize="off"
        />
      </div>
      <div className="field">
        <label htmlFor={`${id}-pw2`}>{confirmLabel}</label>
        <input
          id={`${id}-pw2`}
          type="password"
          value={confirm}
          onChange={(e) => onConfirm(e.target.value)}
          autoComplete={autoComplete}
          minLength={minLength}
          required
          disabled={disabled}
          spellCheck={false}
          autoCorrect="off"
          autoCapitalize="off"
        />
        {showNow && error && (
          <div className="error-text" role="alert">{error}</div>
        )}
      </div>
      {hint && <div className="hint">{hint}</div>}
    </>
  )
}
