package authz

import "testing"

func TestNormalizeImplication(t *testing.T) {
	cases := []struct {
		name    string
		in      Bit
		mustHas []Bit
		mustNot []Bit
	}{
		{
			name:    "下载隐含预览与打印",
			in:      Download,
			mustHas: []Bit{Download, Preview, Display, Print},
			mustNot: []Bit{Copy, Edit},
		},
		{
			name:    "预览隐含可见",
			in:      Preview,
			mustHas: []Bit{Preview, Display},
			mustNot: []Bit{Download},
		},
		{
			name:    "授权管理链式补齐",
			in:      ManageACL,
			mustHas: []Bit{ManageACL, ShareInternal, Display},
			mustNot: []Bit{ShareExternal},
		},
		{
			name:    "所有者即全部",
			in:      Owner,
			mustHas: []Bit{Owner, ManageACL, ShareExternal, Delete, Download},
			mustNot: nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Normalize(c.in)
			for _, b := range c.mustHas {
				if !got.Has(b) {
					t.Fatalf("期望包含 %s，实际 %v", b.Name(), got.Names())
				}
			}
			for _, b := range c.mustNot {
				if got.Has(b) {
					t.Fatalf("不应包含 %s，实际 %v", b.Name(), got.Names())
				}
			}
		})
	}
}

func TestPresetsMatchSpec(t *testing.T) {
	c := PresetContributor.Bits()
	if !c.Has(Print) {
		t.Fatal("贡献者应可打印")
	}
	if c.Has(Copy) {
		t.Fatal("贡献者不应可复制：复制属编辑者能力（FSD §3.3）")
	}

	e := PresetEditor.Bits()
	if !e.Has(Copy) || !e.Has(Edit) || !e.Has(Rename) {
		t.Fatalf("编辑者应含 copy/edit/rename，实际 %v", e.Names())
	}
	if e.Has(Delete) {
		t.Fatal("编辑者不应可删除")
	}

	m := PresetManager.Bits()
	for _, b := range []Bit{Move, Delete, ShareInternal, ManageVersion} {
		if !m.Has(b) {
			t.Fatalf("管理者应含 %s", b.Name())
		}
	}
	if m.Has(ShareExternal) || m.Has(ManageACL) {
		t.Fatal("管理者不应可对外分享或授权")
	}

	if PresetOwner.Bits() != AllBits {
		t.Fatal("所有者应为全部位")
	}
}

func TestGrantable(t *testing.T) {
	if err := Grantable(PresetEditor.Level(), PresetManager); err == nil {
		t.Fatal("编辑者不应能授出管理者")
	} else if _, ok := err.(*CeilingError); !ok {
		t.Fatalf("期望 CeilingError，实际 %T", err)
	}

	if err := Grantable(PresetEditor.Level(), PresetEditor); err != nil {
		t.Fatalf("编辑者应能授出编辑者: %v", err)
	}

	if err := Grantable(PresetManager.Level(), PresetOwner); err == nil {
		t.Fatal("管理者不应能授出所有者")
	}

	if err := Grantable(PresetOwner.Level(), PresetOwner); err != nil {
		t.Fatalf("所有者应能授出所有者: %v", err)
	}
}

func TestParseBits(t *testing.T) {
	got, err := ParseBits("download, share_external")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if !got.Has(Display) {
		t.Fatal("download 应连带 display")
	}
	if _, err := ParseBits("download,fly"); err == nil {
		t.Fatal("未知位名必须报错，不可静默忽略")
	}
}

func TestIsSingle(t *testing.T) {
	if !Download.IsSingle() {
		t.Fatal("单个位应通过")
	}
	if (Download | Preview).IsSingle() {
		t.Fatal("多位不应通过")
	}
	if Bit(0).IsSingle() {
		t.Fatal("空位不应通过")
	}
	if Bit(1 << 20).IsSingle() {
		t.Fatal("超出 15 位的位不应通过")
	}
}
