package content

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
)

// MaxSVGBytes 是净化后的 SVG 上限。SVG 是文本，正常业务图不会超过这个量级；
// 超大 SVG 往往是"用图形做 DoS"（几百万个节点让浏览器卡死）。
const MaxSVGBytes = 2 << 20

// ErrSVGUnsafe 表示 SVG 含无法安全净化的结构（如 DOCTYPE/外部实体）。
var ErrSVGUnsafe = errors.New("SVG 含有不允许的结构")

// dropElements 是整个元素连同子树一起删除的标签。
//
// 判据：这些标签能执行脚本、加载外部资源、或改变文档的行为语义。
// 只做"删除属性"是不够的：<script> 里没有属性也能执行。
var dropElements = map[string]bool{
	"script":           true,
	"foreignobject":    true,
	"iframe":           true,
	"embed":            true,
	"object":           true,
	"handler":          true,
	"listener":         true,
	"set":              true, // SMIL：可以在无脚本的情况下改属性
	"animate":          true,
	"animatemotion":    true,
	"animatetransform": true,
}

// LooksLikeSVG 判断内容是否为 SVG。
//
// 三重判据（扩展名/声明 MIME/内容开头）：攻击者常把 SVG 存成 .png 上传，
// 只信扩展名等于没检查；反过来只信内容也会误伤（部分导出工具写 BOM）。
func LooksLikeSVG(name, mime string, head []byte) bool {
	lower := strings.ToLower(name)
	if strings.HasSuffix(lower, ".svg") || strings.HasSuffix(lower, ".svgz") {
		return true
	}
	if strings.Contains(strings.ToLower(mime), "image/svg") {
		return true
	}
	trimmed := bytes.TrimSpace(bytes.TrimPrefix(head, []byte{0xEF, 0xBB, 0xBF}))
	return bytes.HasPrefix(trimmed, []byte("<svg")) ||
		(bytes.HasPrefix(trimmed, []byte("<?xml")) && bytes.Contains(trimmed, []byte("<svg")))
}

// SanitizeSVG 用白名单方式重写 SVG：删除危险元素与属性。
//
// 为什么不用正则"删掉 script 标签"：
// XML 里等价写法太多（大小写、命名空间前缀、CDATA 包裹、属性里的事件处理器），
// 正则删不全，而漏一个就等于没做。这里用真正的 XML 解析器，
// 只看解析后的元素名与属性名——它们已经被规范化。
//
// 明确拒绝 DOCTYPE：encoding/xml 不解析外部实体，遇到 DOCTYPE 会报错；
// 与其依赖"解析失败"来拦，不如显式拒绝并给出明确原因（避免绕过解析器的变体）。
func SanitizeSVG(src []byte) ([]byte, error) {
	if len(src) > MaxSVGBytes {
		return nil, fmt.Errorf("SVG 超过 %d 字节上限", MaxSVGBytes)
	}
	if bytes.Contains(bytes.ToUpper(src), []byte("<!DOCTYPE")) {
		return nil, ErrSVGUnsafe
	}

	dec := xml.NewDecoder(bytes.NewReader(src))
	dec.Strict = false
	dec.Entity = xml.HTMLEntity

	var out bytes.Buffer
	out.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)

	// 命名空间 URI -> 前缀。
	//
	// Go 的 XML 解码器会把属性/元素的前缀**解析成完整 URI** 放进 Name.Space，
	// 因此不能直接把 Space 当前缀写回去（那会产出
	// `http://www.w3.org/1999/xlink:href` 这种非法属性名）。
	// 这里边解析边记录文档自己声明的 xmlns:前缀，写回时再映射回去。
	nsPrefix := map[string]string{}

	// skip 记录当前处于"被丢弃元素"的嵌套深度
	skipDepth := 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("SVG 解析失败: %w", err)
		}

		switch t := tok.(type) {
		case xml.StartElement:
			name := strings.ToLower(t.Name.Local)
			if skipDepth > 0 {
				skipDepth++
				continue
			}
			if dropElements[name] {
				skipDepth = 1
				continue
			}
			// 先登记本元素上的命名空间声明，再写属性：
			// 同一元素里 `xmlns:xlink` 与其使用是完全合法的写法，
			// 只扫一遍的话会漏掉"声明在使用之后"的情况。
			for _, a := range t.Attr {
				if a.Name.Space == "xmlns" && a.Name.Local != "" {
					nsPrefix[a.Value] = a.Name.Local
				}
			}
			out.WriteByte('<')
			out.WriteString(t.Name.Local)
			for _, a := range t.Attr {
				name := attrName(a, nsPrefix)
				if name == "" || !safeAttr(name, a.Value) {
					continue
				}
				out.WriteByte(' ')
				out.WriteString(name)
				out.WriteString(`="`)
				xml.EscapeText(&out, []byte(a.Value))
				out.WriteString(`"`)
			}
			out.WriteByte('>')

		case xml.EndElement:
			if skipDepth > 0 {
				skipDepth--
				continue
			}
			out.WriteString(`</`)
			out.WriteString(t.Name.Local)
			out.WriteByte('>')

		case xml.CharData:
			if skipDepth == 0 {
				xml.EscapeText(&out, t)
			}

		case xml.Comment, xml.ProcInst, xml.Directive:
			// 注释与处理指令一律丢弃：注释可用于条件注释型 XSS 的变体，
			// 处理指令（如 xml-stylesheet）可以引入外部资源。
			continue
		}
	}

	if out.Len() > MaxSVGBytes {
		return nil, fmt.Errorf("净化后 SVG 仍然过大")
	}
	return out.Bytes(), nil
}

// attrName 还原属性的完整书写形式（含前缀）。
//
// Go 的 XML 解码器已把前缀解析成 URI：
//
//	href            -> Space="",                        Local="href"
//	xlink:href      -> Space="http://www.w3.org/1999/xlink", Local="href"
//	xmlns:xlink="…" -> Space="xmlns",                   Local="xlink"
//
// 早先的实现无条件写成 "xmlns:"+Space+":"+Local，于是 `xlink:href` 变成
// `xmlns:http://www.w3.org/1999/xlink:href`、命名空间声明变成 `xmlns:xmlns:xlink`——
// 两者都是非法 XML，属性被浏览器整条丢弃，用 <use xlink:href="#icon"> 引用的
// 图标/渐变/蒙版全部失效（净化器把文件改坏了，而且没有任何报错）。
//
// 返回空串表示该属性必须丢弃：解析不回去的命名空间宁可去掉，也不写出非法标记。
func attrName(a xml.Attr, nsPrefix map[string]string) string {
	switch {
	case a.Name.Space == "":
		return a.Name.Local
	case a.Name.Space == "xmlns":
		// 命名空间声明本身要保留，否则后面的 xlink:href 无处可依
		if a.Name.Local == "" {
			return "xmlns"
		}
		return "xmlns:" + a.Name.Local
	case a.Name.Local == "":
		return ""
	default:
		if p, ok := nsPrefix[a.Name.Space]; ok {
			return p + ":" + a.Name.Local
		}
		// 没声明过的前缀会以 URI 形式出现在 Space 里；把它当前缀会写出非法属性名
		if strings.Contains(a.Name.Space, "://") {
			return ""
		}
		return a.Name.Space + ":" + a.Name.Local
	}
}

// safeAttr 判断属性是否可以保留。
func safeAttr(name, value string) bool {
	lower := strings.ToLower(name)
	// 所有事件处理器
	if strings.HasPrefix(lower, "on") {
		return false
	}
	// href/xlink:href 里的脚本与数据 URI
	if lower == "href" || lower == "src" || lower == "xlink:href" {
		v := strings.ToLower(strings.TrimSpace(value))
		v = strings.ReplaceAll(v, "\t", "")
		v = strings.ReplaceAll(v, "\n", "")
		v = strings.ReplaceAll(v, " ", "")
		if strings.HasPrefix(v, "javascript:") || strings.HasPrefix(v, "data:text/html") ||
			strings.HasPrefix(v, "vbscript:") {
			return false
		}
	}
	// style 里可以带 expression()/url(javascript:)
	if lower == "style" {
		v := strings.ToLower(value)
		if strings.Contains(v, "javascript:") || strings.Contains(v, "expression(") ||
			strings.Contains(v, "url(") {
			return false
		}
	}
	return true
}
