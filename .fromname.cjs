const fs = require('fs')
function patch(p, pairs) {
  let raw = fs.readFileSync(p, 'utf8')
  const crlf = raw.includes('\r\n')
  let s = crlf ? raw.replace(/\r\n/g, '\n') : raw
  for (const [a, b] of pairs) {
    if (!s.includes(a)) throw new Error('miss in ' + p + ' :: ' + a.slice(0, 60))
    s = s.replace(a, b)
  }
  if (crlf) s = s.replace(/\n/g, '\r\n')
  fs.writeFileSync(p, s)
  console.log('patched', p)
}

// 1) Message 携带发件人显示名
patch('internal/notify/notify.go', [[
  `	// ReplyTo 是回复地址。留空表示不写该头（回复即回到发件人）。
	// 典型用法：发件人用 noreply@ 地址，但希望收件人的回信进客服邮箱。
	ReplyTo string`,
  `	// ReplyTo 是回复地址。留空表示不写该头（回复即回到发件人）。
	// 典型用法：发件人用 noreply@ 地址，但希望收件人的回信进客服邮箱。
	ReplyTo string
	// FromName 是发件人显示名（如"森莘科创文档中心"）。
	//
	// 为什么要挂在消息上而不是只放在通道配置里：显示名是**按租户**变化的
	// （租户品牌不同），而平台默认 SMTP 通道是全局的、不知道当前是哪个租户。
	// 放在消息上，发送端就能覆盖通道里的默认值；留空则沿用通道配置。
	FromName string`,
]])

// 2) 统一品牌显示名规则
patch('internal/notify/settings.go', [[
  `func DefaultFromName(brand string) string {
	brand = strings.TrimSpace(brand)
	if brand == "" {
		brand = "NeuroDMS"
	}
	return "【" + brand + "文档管理系统】"
}`,
  `func DefaultFromName(brand string) string { return BrandDisplayName(brand) }

// BrandDisplayName 把租户品牌名补成发件人显示名：**企业名 + "文档中心"**。
//
// 三条规则，避免历史上出现过的问题：
//   - 空品牌 → "NeuroDMS文档中心"（不能让显示名退化成邮箱地址）；
//   - 已经以"文档中心"/"文档管理系统"结尾 → 原样返回。曾经有租户把品牌名
//     直接填成"文档中心"，无脑拼接会变成"文档中心文档中心"；
//   - 其余情况追加"文档中心"（如"森莘科创" → "森莘科创文档中心"）。
func BrandDisplayName(brand string) string {
	b := strings.TrimSpace(brand)
	if b == "" {
		b = "NeuroDMS"
	}
	if strings.HasSuffix(b, "文档中心") || strings.HasSuffix(b, "文档管理系统") {
		return b
	}
	return b + "文档中心"
}`,
]])

// 3) SMTP：消息里的显示名优先于通道配置
patch('internal/notify/smtp.go', [[
  `	raw := BuildMIME(s.cfg.From, m)`,
  `	// 显示名优先用消息自带的（按租户品牌），其次用通道配置里的 from 串。
	// 平台默认通道只在配置里放了地址，不覆盖的话收件人只会看到一个邮箱。
	from := s.cfg.From
	if name := strings.TrimSpace(m.FromName); name != "" {
		from = formatFrom(name, addrOf(s.cfg.From))
	}
	raw := BuildMIME(from, m)`,
]])

// 4) Graph：消息里的显示名同样优先
patch('internal/notify/graph.go', [[
  `	if strings.TrimSpace(s.cfg.FromName) != "" {`,
  `	fromName := strings.TrimSpace(m.FromName)
	if fromName == "" {
		fromName = strings.TrimSpace(s.cfg.FromName)
	}
	if fromName != "" {`,
], [
  `				"name":    s.cfg.FromName,`,
  `				"name":    fromName,`,
]])

// 5) 验证码邮件：主题与显示名统一
patch('internal/bootstrap/notify.go', [[
  `	msg := notify.Message{
		To:      to,
		Subject: "【" + brand + "】验证码",
		Text: fmt.Sprintf("您在%s的验证码是 %s，%d 分钟内有效。\n如非本人操作，请忽略本邮件。",
			brand, code, 10),`,
  `	// 显示名与主题统一走同一规则（企业名 + 文档中心），
	// 避免"发件人一个名字、主题另一个名字"。
	display := notify.BrandDisplayName(brand)
	msg := notify.Message{
		To:       to,
		FromName: display,
		Subject:  "【" + display + "】验证码",
		Text: fmt.Sprintf("您在%s的验证码是 %s，%d 分钟内有效。\n如非本人操作，请忽略本邮件。",
			display, code, 10),`,
], [
  `			html.EscapeString(brand), code),`,
  `			html.EscapeString(display), code),`,
]])
