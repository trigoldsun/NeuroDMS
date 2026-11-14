// Package netinfo 把访问记录里的原始 IP / User-Agent 翻译成人能读的信息。
//
// 只做三件小事：
//  1. 判断 IP 属于内网还是公网（不依赖任何库）；
//  2. 可选地查 IP 归属地（配置了 GeoLite2 mmdb 才有，未配置时明确说"未启用"）；
//  3. 从 UA 里解析浏览器与操作系统。
//
// 刻意不做"设备指纹"或"主机名解析"：前者是灰色手段，后者在浏览器里根本拿不到
// （见 docs/31 §7.8 的说明）。这里只呈现服务端真实拥有的信息。
package netinfo

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/oschwald/maxminddb-golang/v2"
)

// Scope 返回 IP 的可见范围：内网 / 公网 / 未知。
func Scope(ip string) string {
	addr := net.ParseIP(strings.TrimSpace(ip))
	if addr == nil {
		return "未知"
	}
	if addr.IsLoopback() {
		return "本机"
	}
	if addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
		return "内网"
	}
	// CGNAT 100.64/10：运营商大内网，既不能当公网也不该显示成"内网"
	if v4 := addr.To4(); v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
		return "运营商内网"
	}
	return "公网"
}

// Geo 是 IP 归属地查询器。未配置数据库时所有查询都返回"未启用"。
type Geo struct {
	db   *maxminddb.Reader
	path string
}

// Open 打开 GeoLite2/GeoIP2 数据库。path 为空时返回 (nil, nil)，表示未启用。
//
// 不让它导致启动失败：归属地是"锦上添花"的信息，缺库时整站不该起不来。
func Open(path string) (*Geo, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	db, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("打开 IP 库失败: %w", err)
	}
	return &Geo{db: db, path: path}, nil
}

// Close 释放数据库句柄。
func (g *Geo) Close() error {
	if g == nil || g.db == nil {
		return nil
	}
	return g.db.Close()
}

// Enabled 报告是否可用（界面据此决定显示"归属地"还是"未启用"）。
func (g *Geo) Enabled() bool { return g != nil && g.db != nil }

// Describe 返回"国家 省/市"这样的短标签；查不到返回空串。
func (g *Geo) Describe(ip string) string {
	if !g.Enabled() {
		return ""
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return ""
	}
	addr = addr.Unmap()
	var rec struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
			Names   struct {
				ZhCN string `maxminddb:"zh-CN"`
			} `maxminddb:"names"`
		} `maxminddb:"country"`
		City struct {
			Names struct {
				ZhCN string `maxminddb:"zh-CN"`
			} `maxminddb:"names"`
		} `maxminddb:"city"`
	}
	res := g.db.Lookup(addr)
	if !res.Found() {
		return ""
	}
	if err := res.Decode(&rec); err != nil {
		return ""
	}
	parts := make([]string, 0, 2)
	if rec.Country.Names.ZhCN != "" {
		parts = append(parts, rec.Country.Names.ZhCN)
	} else if rec.Country.ISOCode != "" {
		parts = append(parts, rec.Country.ISOCode)
	}
	if rec.City.Names.ZhCN != "" {
		parts = append(parts, rec.City.Names.ZhCN)
	}
	return strings.Join(parts, " ")
}

// IsOverseas 判断是否境外 IP。没有 IP 库时无法判断，返回 false（宁可不报，不乱报）。
func (g *Geo) IsOverseas(ip string) bool {
	if !g.Enabled() {
		return false
	}
	addr, perr := netip.ParseAddr(strings.TrimSpace(ip))
	if perr != nil {
		return false
	}
	var rec struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	res := g.db.Lookup(addr.Unmap())
	if !res.Found() {
		return false
	}
	if err := res.Decode(&rec); err != nil {
		return false
	}
	return rec.Country.ISOCode != "" && rec.Country.ISOCode != "CN"
}

// UserAgent 是人类可读的客户端描述。
type UserAgent struct {
	Browser string `json:"browser"`
	OS      string `json:"os"`
}

// DescribeUA 从 User-Agent 里提取浏览器与操作系统。
//
// 只用特征串判断，不引第三方库：这里的目标是"让审计里的人看得懂"，
// 不是做精确统计。识别不出来就返回"其他"，不要瞎猜。
func DescribeUA(ua string) UserAgent {
	l := strings.ToLower(ua)
	out := UserAgent{Browser: "其他", OS: "其他"}

	switch {
	case strings.Contains(l, "micromessenger"):
		out.Browser = "微信内置浏览器"
	case strings.Contains(l, "dingtalk"):
		out.Browser = "钉钉内置浏览器"
	case strings.Contains(l, "lark") || strings.Contains(l, "feishu"):
		out.Browser = "飞书内置浏览器"
	case strings.Contains(l, "wxwork"):
		out.Browser = "企业微信内置浏览器"
	case strings.Contains(l, "edg/"):
		out.Browser = "Edge"
	case strings.Contains(l, "opr/") || strings.Contains(l, "opera"):
		out.Browser = "Opera"
	case strings.Contains(l, "firefox/"):
		out.Browser = "Firefox"
	case strings.Contains(l, "chrome/") || strings.Contains(l, "crios"):
		out.Browser = "Chrome"
	case strings.Contains(l, "safari/"):
		out.Browser = "Safari"
	}

	switch {
	case strings.Contains(l, "windows nt 10"):
		out.OS = "Windows 10/11"
	case strings.Contains(l, "windows"):
		out.OS = "Windows"
	case strings.Contains(l, "iphone") || strings.Contains(l, "ipad") || strings.Contains(l, "ios"):
		out.OS = "iOS/iPadOS"
	case strings.Contains(l, "android"):
		out.OS = "Android"
	case strings.Contains(l, "mac os x") || strings.Contains(l, "macintosh"):
		out.OS = "macOS"
	case strings.Contains(l, "linux"):
		out.OS = "Linux"
	}
	return out
}
