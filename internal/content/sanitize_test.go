package content

import (
	"bytes"
	"encoding/xml"
	"io"
	"strings"
	"testing"
)

// SVG 净化是"只要漏一个变体就等于没做"的典型场景，
// 所以这里逐个变体钉死，而不是只测一个 <script>。

func TestSanitizeSVGRemovesScript(t *testing.T) {
	src := `<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script><rect width="10" height="10"/></svg>`
	out, err := SanitizeSVG([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(strings.ToLower(s), "<script") || strings.Contains(s, "alert(1)") {
		t.Fatalf("script 未被移除: %s", s)
	}
	if !strings.Contains(s, "rect") {
		t.Fatalf("正常元素被误删: %s", s)
	}
}

func TestSanitizeSVGRemovesEventHandlers(t *testing.T) {
	src := `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><rect onClick="x()" width="1"/></svg>`
	out, _ := SanitizeSVG([]byte(src))
	s := strings.ToLower(string(out))
	if strings.Contains(s, "onload") || strings.Contains(s, "onclick") {
		t.Fatalf("事件属性未被移除: %s", s)
	}
	if !strings.Contains(s, `width="1"`) {
		t.Fatalf("正常属性被误删: %s", s)
	}
}

// javascript: 伪协议可以用制表符/换行/空格绕过简单字符串匹配。
func TestSanitizeSVGRemovesJSURL(t *testing.T) {
	cases := []string{
		`<svg xmlns="http://www.w3.org/2000/svg"><a href="javascript:alert(1)"><text>x</text></a></svg>`,
		`<svg xmlns="http://www.w3.org/2000/svg"><a href="java	script:alert(1)"><text>x</text></a></svg>`,
		`<svg xmlns="http://www.w3.org/2000/svg"><a href="data:text/html;base64,PHNjcmlwdD4="><text>x</text></a></svg>`,
	}
	for i, src := range cases {
		out, _ := SanitizeSVG([]byte(src))
		if strings.Contains(strings.ToLower(string(out)), "javascript:") ||
			strings.Contains(strings.ToLower(string(out)), "data:text/html") {
			t.Fatalf("第 %d 个变体未清理: %s", i+1, out)
		}
	}
}

func TestSanitizeSVGRemovesStyleExpression(t *testing.T) {
	src := `<svg xmlns="http://www.w3.org/2000/svg"><rect style="width:expression(alert(1))"/></svg>`
	out, _ := SanitizeSVG([]byte(src))
	if strings.Contains(strings.ToLower(string(out)), "expression(") {
		t.Fatalf("style 表达式未清理: %s", out)
	}
}

// 明确拒绝 DOCTYPE：外部实体（XXE）与参数实体变体都从这里来。
func TestSanitizeSVGRejectsDoctype(t *testing.T) {
	src := `<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>`
	if _, err := SanitizeSVG([]byte(src)); err == nil {
		t.Fatal("含 DOCTYPE 的 SVG 必须拒绝")
	}
}

func TestSanitizeSVGRejectsOversize(t *testing.T) {
	big := bytes.Repeat([]byte("a"), MaxSVGBytes+1)
	if _, err := SanitizeSVG(big); err == nil {
		t.Fatal("超大 SVG 必须拒绝")
	}
}

func TestLooksLikeSVG(t *testing.T) {
	if !LooksLikeSVG("a.svg", "", nil) {
		t.Fatal("扩展名应识别")
	}
	if !LooksLikeSVG("a.png", "image/svg+xml", nil) {
		t.Fatal("声明 MIME 应识别（改扩展名上传是常见绕过）")
	}
	if !LooksLikeSVG("a.png", "image/png", []byte("  <svg xmlns=...")) {
		t.Fatal("内容开头应识别")
	}
	if LooksLikeSVG("a.txt", "text/plain", []byte("hello")) {
		t.Fatal("普通文本不应误判")
	}
	if !LooksLikeSVG("a.svg", "", []byte("\xEF\xBB\xBF<svg")) {
		t.Fatal("带 BOM 的 SVG 应识别")
	}
}

// 命名空间前缀必须原样保留。
//
// 曾经的实现把前缀写成 "xmlns:"+Space+":"+Local，产出
// `xmlns:xlink:href` 与 `xmlns:xmlns:xlink` 这种非法属性名。
// 危害不是"好看不好看"：属性被浏览器丢弃后，用 <use xlink:href="#icon">
// 引用的图标、渐变、蒙版全部失效——净化器把文件改坏了。
func TestSanitizeSVGPreservesNamespacePrefixes(t *testing.T) {
	src := `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">` +
		`<defs><path id="p" d="M0 0"/></defs><use xlink:href="#p"/></svg>`
	out, err := SanitizeSVG([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "xmlns:xmlns") {
		t.Fatalf("命名空间声明被重复加前缀: %s", s)
	}
	if strings.Contains(s, "xmlns:xlink:href") {
		t.Fatalf("xlink:href 被错误改写成 xmlns:xlink:href: %s", s)
	}
	if !strings.Contains(s, `xmlns:xlink="http://www.w3.org/1999/xlink"`) {
		t.Fatalf("命名空间声明丢失: %s", s)
	}
	if !strings.Contains(s, `xlink:href="#p"`) {
		t.Fatalf("xlink:href 未保留: %s", s)
	}
}

// 净化产物必须仍能被 XML 解析器读回去——这是"没把文件改坏"的最后一道断言。
func TestSanitizeSVGOutputIsWellFormed(t *testing.T) {
	src := `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">` +
		`<g><use xlink:href="#a"/><rect width="2" height="3" fill="red"/></g></svg>`
	out, err := SanitizeSVG([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	dec := xml.NewDecoder(bytes.NewReader(out))
	for {
		if _, err := dec.Token(); err != nil {
			if err == io.EOF {
				return
			}
			t.Fatalf("净化后不是合法 XML: %v\n%s", err, out)
		}
	}
}
