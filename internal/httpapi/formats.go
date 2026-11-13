package httpapi

// 文件格式目录：设置页"允许上传的格式"的清单 + 每个格式的预览能力。
//
// 为什么放后端而不是前端硬编码：
//   预览能力取决于**这台服务器实际装了什么**——LibreOffice 有没有就绪、
//   音视频转码有没有启用。前端写死一份清单，迟早会出现"标着能看、点开 500"，
//   而且这种漂移只有用户点开才会发现。
//   这里按运行时能力现算，前端只负责渲染。

import (
	"net/http"
	"strings"
)

// 预览能力的四种取值。
//
// 前端的徽标文案与这个一一对应，不要另造词：
//
//	native  —— 浏览器直接渲染（图片/PDF/文本/音视频）
//	wasm    —— 前端 wasm 解码（HEIC/HEIF，服务端不解码，原样返回字节）
//	convert —— 服务端转换或转码后返回（office 文档、部分视频容器）
//	none    —— 不支持在线预览，只能下载
const (
	previewNative  = "native"
	previewWasm    = "wasm"
	previewConvert = "convert"
	previewNone    = "none"
)

type formatItem struct {
	Ext     string `json:"ext"`
	Name    string `json:"name"`
	Preview string `json:"preview"`
}

type formatGroup struct {
	Label string       `json:"label"`
	Items []formatItem `json:"items"`
}

// formatSpec 是清单本体：只写"扩展名 + 显示名"，预览能力在运行时判定。
// 顺序按国内办公习惯排，常用的在前面——设置页是给人翻的，不是给机器读的。
var formatSpec = []struct {
	Label string
	Items [][2]string // [ext, name]
}{
	{
		Label: "文档",
		Items: [][2]string{
			{".pdf", "PDF"}, {".doc", "Word 97-2003"}, {".docx", "Word"},
			{".rtf", "RTF"}, {".odt", "OpenDocument 文本"}, {".wps", "WPS 文字"},
			{".ofd", "OFD 版式文档"}, {".epub", "EPUB"}, {".mobi", "MOBI"},
			{".tex", "LaTeX"}, {".pages", "Pages"}, {".one", "OneNote"},
			{".vsd", "Visio 97-2003"}, {".vsdx", "Visio"},
		},
	},
	{
		Label: "表格",
		Items: [][2]string{
			{".xls", "Excel 97-2003"}, {".xlsx", "Excel"}, {".csv", "CSV"},
			{".tsv", "TSV"}, {".ods", "OpenDocument 表格"}, {".et", "WPS 表格"},
			{".numbers", "Numbers"},
		},
	},
	{
		Label: "演示",
		Items: [][2]string{
			{".ppt", "PowerPoint 97-2003"}, {".pptx", "PowerPoint"}, {".pps", "PowerPoint 放映"},
			{".ppsx", "PowerPoint 放映（x）"}, {".odp", "OpenDocument 演示"}, {".dps", "WPS 演示"},
			{".key", "Keynote"},
		},
	},
	{
		Label: "图片",
		Items: [][2]string{
			{".jpg", "JPEG"}, {".jpeg", "JPEG（.jpeg）"}, {".png", "PNG"}, {".gif", "GIF"},
			{".webp", "WebP"}, {".bmp", "BMP"}, {".svg", "SVG"}, {".ico", "图标 ICO"},
			{".avif", "AVIF"}, {".heic", "HEIC（iPhone）"}, {".heif", "HEIF"},
			{".tif", "TIFF"}, {".tiff", "TIFF（.tiff）"},
			{".psd", "Photoshop"}, {".ai", "Illustrator"},
			{".cr2", "佳能 RAW（CR2）"}, {".cr3", "佳能 RAW（CR3）"}, {".nef", "尼康 RAW"},
			{".arw", "索尼 RAW"}, {".dng", "DNG"}, {".orf", "奥林巴斯 RAW"},
			{".rw2", "松下 RAW"}, {".raf", "富士 RAW"}, {".pef", "宾得 RAW"},
		},
	},
	{
		Label: "音视频",
		Items: [][2]string{
			{".mp4", "MP4"}, {".m4v", "M4V"}, {".mov", "QuickTime"}, {".webm", "WebM"},
			{".mkv", "Matroska"}, {".avi", "AVI"}, {".wmv", "WMV"}, {".flv", "FLV"},
			{".mpg", "MPEG"}, {".mpeg", "MPEG（.mpeg）"}, {".3gp", "3GP"}, {".ogv", "OGG 视频"},
			{".mp3", "MP3"}, {".wav", "WAV"}, {".m4a", "M4A"}, {".ogg", "OGG 音频"},
			{".flac", "FLAC"}, {".aac", "AAC"}, {".ape", "APE"}, {".wma", "WMA"},
		},
	},
	{
		Label: "压缩包",
		Items: [][2]string{
			{".zip", "ZIP"}, {".rar", "RAR"}, {".7z", "7-Zip"}, {".tar", "TAR"},
			{".gz", "GZIP"}, {".tgz", "TGZ"}, {".bz2", "BZIP2"}, {".xz", "XZ"},
		},
	},
	{
		Label: "代码与配置",
		Items: [][2]string{
			{".txt", "纯文本"}, {".md", "Markdown"}, {".log", "日志"},
			{".json", "JSON"}, {".xml", "XML"}, {".yaml", "YAML"}, {".yml", "YAML（.yml）"},
			{".toml", "TOML"}, {".ini", "INI"}, {".conf", "配置文件"}, {".sql", "SQL"},
			{".html", "HTML"}, {".htm", "HTML（.htm）"}, {".css", "CSS"},
			{".js", "JavaScript"}, {".ts", "TypeScript"}, {".py", "Python"},
			{".java", "Java"}, {".go", "Go"}, {".sh", "Shell"},
		},
	},
	{
		Label: "邮件与其他",
		Items: [][2]string{
			{".eml", "邮件（EML）"}, {".msg", "Outlook 邮件"}, {".dwg", "AutoCAD DWG"},
			{".dxf", "AutoCAD DXF"}, {".sketch", "Sketch"}, {".pcap", "网络抓包"},
		},
	},
}

// officeExts 是能交给 LibreOffice 转换的格式。
// 只有转换器就绪时才标"可预览"——server 镜像里没装或启动失败时，
// 标了就是骗用户。
var officeExts = map[string]bool{
	".doc": true, ".docx": true, ".rtf": true, ".odt": true, ".wps": true,
	".xls": true, ".xlsx": true, ".ods": true, ".et": true,
	".ppt": true, ".pptx": true, ".pps": true, ".ppsx": true, ".odp": true, ".dps": true,
}

// 需要转码才能在浏览器播放的视频容器。
// mp4/m4v/mov/webm/ogv 里若是 H.264/VP9 浏览器能直接播，其余的容器大概率不行。
var transcodeVideoExts = map[string]bool{
	".mkv": true, ".avi": true, ".wmv": true, ".flv": true,
	".mpg": true, ".mpeg": true, ".3gp": true,
}

// 浏览器自己不认、当前也没有转换通道的图片格式。
// 标 none 而不是让用户点开看破图。
var noPreviewImageExts = map[string]bool{
	".tif": true, ".tiff": true, ".psd": true, ".ai": true,
}

// previewKind 按运行时能力判定某个扩展名的预览方式。
func (a *API) previewKind(ext string) string {
	e := strings.ToLower(ext)

	switch {
	case e == ".heic" || e == ".heif":
		// 服务端不解码，原样返回字节，前端 wasm 转码
		return previewWasm
	case rawExts[e]:
		// 相机 RAW：由 LibRaw 解码（单张 3~11 秒；有内嵌图时先给首屏）
		if a.Raw != nil && a.Raw.Available() {
			return previewConvert
		}
		return previewNone
	case noPreviewImageExts[e]:
		return previewNone
	case officeExts[e]:
		if a.Preview != nil {
			return previewConvert
		}
		return previewNone
	case transcodeVideoExts[e]:
		if a.Media != nil {
			return previewConvert
		}
		return previewNone
	}

	m := mimeByExt("x" + e)
	switch {
	case m == "application/pdf":
		return previewNative
	case strings.HasPrefix(m, "image/"):
		return previewNative
	case strings.HasPrefix(m, "audio/"), strings.HasPrefix(m, "video/"):
		return previewNative
	case strings.HasPrefix(m, "text/"), m == "application/json", m == "application/xml":
		return previewNative
	}
	// 压缩包、邮件、CAD、HTML（同源渲染有 XSS 风险，走下载）等
	return previewNone
}

// handleFormatCatalog 返回设置页需要的格式清单与预览能力。
func (a *API) handleFormatCatalog(w http.ResponseWriter, r *http.Request) {
	groups := make([]formatGroup, 0, len(formatSpec))
	total, viewable := 0, 0
	for _, g := range formatSpec {
		items := make([]formatItem, 0, len(g.Items))
		for _, it := range g.Items {
			kind := a.previewKind(it[0])
			total++
			if kind != previewNone {
				viewable++
			}
			items = append(items, formatItem{Ext: it[0], Name: it[1], Preview: kind})
		}
		groups = append(groups, formatGroup{Label: g.Label, Items: items})
	}
	writeOK(w, r, map[string]any{
		"groups":   groups,
		"total":    total,
		"viewable": viewable,
		// 转换与转码能力随部署而变，明确告诉前端当前这台服务器能做什么
		"officeReady":     a.Preview != nil,
		"mediaTranscoder": a.Media != nil,
	})
}
