// Package watermark 在 PDF 上叠加溯源水印。
//
// 为什么用 pdfcpu 而不是 Ghostscript：
//   - 许可：Ghostscript 是 AGPLv3，私有化闭源分发与 SaaS 部署都需商业授权
//     （Artifex 官方 FAQ 明确说明）；pdfcpu 是 Apache-2.0，无附加义务。
//   - 攻击面：预览链路要把用户上传的不可信文件喂给解析器。pdfcpu 是纯 Go（内存安全），
//     Ghostscript 是 C 解释器，历史上是 CVE 高发目标。
//
// 字体限制（重要）：
//
//	本版本水印使用 PDF 内置的 Helvetica，只支持 ASCII。
//	中文水印需要 TrueType(glyf) 轮廓的中文字体——容器里的 Noto Sans CJK 是
//	OpenType/CFF 轮廓，pdfcpu 会拒绝（"unsupported font format: OpenType CFF"）。
//	因此水印内容使用**账号名 / 邮箱 / IP / 时间**（均为 ASCII），
//	溯源能力不受影响（账号名是唯一的，且与真实身份可对账）。
//	若后续需要中文显示名，只需换一份 glyf 轮廓的 OFL 中文字体并调用 InstallFonts，
//	调用方不需要改。
package watermark

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
)

// 错误分类。调用方据此决定是"拒绝预览"还是"降级"——
// 但本项目一律拒绝：水印失败时返回原 PDF，等于水印静默失效。
var (
	ErrEmptyText = errors.New("水印文字为空")
	ErrApply     = errors.New("水印叠加失败")
)

// Service 是 PDF 水印服务。零值不可用，须用 New 构造。
type Service struct {
	mu sync.Mutex // pdfcpu 的字体仓库与配置不是并发安全的，串行化以保守处理
	// conf 复用一个配置：每次新建会重复加载字体资源，开销不小
	conf *model.Configuration
	// font 是叠加文字用的字体名。为空表示回退到内置 Helvetica（仅 ASCII）。
	// 内置字体无需安装、无许可问题，但渲染不了中文——这是"能不能显示中文名"的分界线。
	font string
}

// New 创建水印服务。
//
// configDir 是 pdfcpu 的资源目录（字体库、配置文件）。必须显式给一个**可写**目录：
// pdfcpu 默认用 os.UserConfigDir()，容器里非 root 用户往往没有 HOME，
// 结果是启动时 panic（实测：config problem: mkdir /home/docvault: permission denied）。
//
// 这里同时把 panic 转成 error：pdfcpu 内部用 fault.Fail 抛 panic 表示致命配置错误，
// 直接让它穿透会把"配置目录不可写"变成一坨栈回溯，掩盖真正原因。
func New(configDir, fontPath string) (svc *Service, err error) {
	defer func() {
		if r := recover(); r != nil {
			svc, err = nil, fmt.Errorf("初始化 PDF 水印失败: %v", r)
		}
	}()

	if configDir != "" {
		if err := os.MkdirAll(configDir, 0o750); err != nil {
			return nil, fmt.Errorf("创建水印资源目录失败: %w", err)
		}
		// pdfcpu 通过 XDG_CONFIG_HOME / HOME 定位资源目录，两者都没有时会 panic。
		// 只在未设置时接管，避免覆盖部署方自己的选择。
		if os.Getenv("XDG_CONFIG_HOME") == "" {
			if err := os.Setenv("XDG_CONFIG_HOME", configDir); err != nil {
				return nil, err
			}
		}
	}

	conf := model.NewDefaultConfiguration()
	conf.Cmd = model.ADDWATERMARKS
	// relaxed：真实业务 PDF 常有轻微不合规（缺 Producer、xref 偏移小错），
	// strict 会把它们全部拒掉，导致"预览打不开"——比水印不生效更容易被投诉。
	conf.ValidationMode = model.ValidationRelaxed

	s := &Service{conf: conf}

	// 安装中文字体（幂等）。失败不算致命：回退 Helvetica 仍能出 ASCII 水印，
	// 但必须在日志里明确"中文名不会显示"，否则现场会以为水印坏了。
	if fontPath != "" {
		if _, statErr := os.Stat(fontPath); statErr != nil {
			return s, fmt.Errorf("中文字体未找到（%s），将回退为 ASCII 水印: %w", fontPath, statErr)
		}
		if err := api.InstallFonts(context.Background(), []string{fontPath}); err != nil {
			return s, fmt.Errorf("安装中文字体失败，将回退为 ASCII 水印: %w", err)
		}
		s.font = "WatermarkSans-Regular"
	}
	return s, nil
}

// asciiText 把水印文字清洗为 Helvetica 能渲染的可见 ASCII。
//
// 非 ASCII（中文名、表情）会被替换为空格并折叠——这不是"丢信息"，
// 因为调用方传入的标识本身就以账号/IP/时间为主；显示名只作补充。
func asciiText(s string) string {
	var b strings.Builder
	prevSpace := false
	for _, r := range s {
		if r >= 0x20 && r < 0x7f {
			b.WriteRune(r)
			prevSpace = r == ' '
			continue
		}
		if !prevSpace {
			b.WriteByte(' ')
			prevSpace = true
		}
	}
	out := strings.TrimSpace(b.String())
	if len([]rune(out)) > 120 {
		out = string([]rune(out)[:120])
	}
	return out
}

// Apply 在每页叠加两层水印：
//
//  1. 页面中央的斜向大字：只放**账号**（短，保证整句落在页宽内）；
//  2. 页脚的水平小字：放完整信息（时间、来源 IP、租户）。
//
// 为什么分两层：单段长文字在斜向平铺时必然超过页宽被裁掉句首（实测：
// "显示名(账号) · 月日时分"即使降到 16pt 仍会截断）。拆成"短标识 + 长明细"
// 后两边都完整：截图一眼看到是谁，取证时页脚能读出精确时间与来源。
func (s *Service) Apply(ctx context.Context, pdf []byte, account, footer string) ([]byte, error) {
	if s.font == "" {
		account, footer = asciiText(account), asciiText(footer)
	} else {
		account, footer = cleanText(account), cleanText(footer)
	}
	if account == "" && footer == "" {
		return nil, ErrEmptyText
	}
	if len(pdf) == 0 {
		return nil, ErrApply
	}
	if account == "" {
		account = footer
	}

	fontName := s.font
	if fontName == "" {
		fontName = "Helvetica"
	}

	// 主水印：固定旋转角度 + 固定字号，**不用 diagonal**。
	//
	// 为什么不用 diagonal：它会把文本自动缩放到页宽，而缩放依据的文本宽度
	// 对中文字符明显偏小（按西文宽度估算），结果是中文水印被放大到超出页面、
	// 句首被裁掉（连续三次实测都被截断）。rotation 模式不做缩放，
	// 给定字号下句子多宽就是多宽，只要小于页宽就一定能完整显示。
	// position 用左下角锚点（l + 底部偏移）而不是居中：
	// pdfcpu 计算文本宽度时对中文明显偏小，居中会导致起点左移、句首被裁；
	// 从左下角起笔则误差只影响右端，只要句子不太长就一定完整。
	main, err := pdfcpu.ParseTextWatermarkDetails(ctx, account,
		"fontname:"+fontName+", points:40, position:l, offset:60 120, "+
			"scalefactor:1.0, opacity:0.16, color:#808080, rotation:45",
		true, types.POINTS, s.conf)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrApply, err)
	}

	// 页脚：水平，信息完整，字号小但清晰
	var wms = []*model.Watermark{main}
	if footer != "" {
		info, ferr := pdfcpu.ParseTextWatermarkDetails(ctx, footer,
			// 同页多个水印时 pdfcpu 要求 opacity/颜色一致（它会共用同一个 ExtGState），
			// 不一致会直接报 inconsistent Opacity。区分靠字号与位置，不靠透明度。
			"fontname:"+fontName+", points:10, position:l, offset:30 34, "+
				"scalefactor:1.0, opacity:0.16, color:#808080, rotation:0",
			true, types.POINTS, s.conf)
		if ferr != nil {
			return nil, fmt.Errorf("%w: %v", ErrApply, ferr)
		}
		wms = append(wms, info)
	}

	// 页码从 1 开始（0 会报 "invalid page number"），所以要显式覆盖每一页
	rs := bytes.NewReader(pdf)
	n, err := api.PageCount(ctx, rs, s.conf)
	if err != nil || n <= 0 {
		return nil, fmt.Errorf("%w: 读取页数失败", ErrApply)
	}
	if _, err := rs.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrApply, err)
	}
	pages := make(map[int][]*model.Watermark, n)
	for i := 1; i <= n; i++ {
		pages[i] = wms
	}

	var buf bytes.Buffer
	s.mu.Lock()
	err = api.AddWatermarksSliceMap(ctx, rs, &buf, pages, s.conf)
	s.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrApply, err)
	}
	return buf.Bytes(), nil
}

// cleanText 保留中文但去掉控制字符与超长内容。
//
// 不做 ASCII 化：已安装 glyf 中文字体时可以正常渲染汉字。
// 控制字符必须清掉——PDF 字符串里的换行会破坏文本操作符。
func cleanText(s string) string {
	var b strings.Builder
	prevSpace := false
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			if !prevSpace {
				b.WriteByte(' ')
				prevSpace = true
			}
			continue
		}
		b.WriteRune(r)
		prevSpace = r == ' '
	}
	out := strings.TrimSpace(b.String())
	if len([]rune(out)) > 120 {
		out = string([]rune(out)[:120])
	}
	return out
}

// HasCJKFont 报告是否已启用中文水印字体（供启动日志与界面提示使用）。
func (s *Service) HasCJKFont() bool { return s.font != "" }

// FooterText 组装页脚明细：时间 → 来源 → 说明。
//
// 这个顺序与截图阅读习惯一致：先看"什么时候"，再看"从哪来"。
func FooterText(at, ip, note string) string {
	parts := make([]string, 0, 3)
	if at != "" {
		parts = append(parts, at)
	}
	if ip != "" {
		parts = append(parts, ip)
	}
	if note != "" {
		parts = append(parts, note)
	}
	return strings.Join(parts, "  ·  ")
}
