// Command licensegen 是本地部署版的**离线**许可证签发工具。
//
// 它与服务端不共享任何密钥：私钥只在本工具里用，服务端只有公钥。
// 所以这个命令**不进 Docker 镜像**（见 docker/server.Dockerfile 只 COPY server），
// 私钥也**不进仓库**：用 -key 指向你自己保管的文件。
//
// 常用：
//
//	# 1) 首次：生成一对密钥（私钥务必离线保管，建议双人分片）
//	licensegen -gen -key ./ed25519.key
//
//	# 2) 签发（永久、不限席位、旗舰版全功能）
//	licensegen -key ./ed25519.key -customer "某某公司" \
//	    -instance <客户端「许可证」页显示的实例指纹>
//
//	# 3) 核对一份许可证
//	licensegen -verify <许可证字符串> -pub <公钥 base64>
//
// 签发结果是一行字符串，客户在「系统设置 → 许可证」里粘贴即可。
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"docvault/internal/license"
)

func main() {
	var (
		keyPath   = flag.String("key", "", "Ed25519 私钥文件路径（PKCS8 PEM；-gen 时写入此处）")
		gen       = flag.Bool("gen", false, "生成新的密钥对并写入 -key，打印公钥后退出")
		customer  = flag.String("customer", "", "客户名称（进许可证，界面上可见）")
		instance  = flag.String("instance", "", "实例指纹（客户端「许可证」页显示），留空表示不绑定机器")
		edition   = flag.String("edition", "business", "档位：basic / professional / business")
		seats     = flag.Int("seats", 0, "席位数上限，0=不限（本地版默认）")
		expires   = flag.String("expires", "", "到期日 YYYY-MM-DD，留空=永久（本地版默认）")
		licenseID = flag.String("id", "", "许可证编号，留空自动生成")
		note      = flag.String("note", "", "备注（合同号等）")
		out       = flag.String("out", "", "把许可证写入文件（默认打印到标准输出）")
		verify    = flag.String("verify", "", "校验一份许可证后退出")
		pub       = flag.String("pub", "", "校验时使用的公钥（base64）")
	)
	flag.Parse()

	if *keyPath == "" {
		fail("必须用 -key 指定私钥文件路径（私钥不入仓库、不入镜像）")
	}

	if *gen {
		if _, err := os.Stat(*keyPath); err == nil {
			fail("私钥文件已存在，拒绝覆盖: " + *keyPath)
		}
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			fail("生成密钥失败: " + err.Error())
		}
		pemBytes, err := marshalPKCS8(privKey)
		if err != nil {
			fail("序列化私钥失败: " + err.Error())
		}
		// 0600：私钥泄露等于所有客户的许可证都能被伪造。
		if err := os.WriteFile(*keyPath, pemBytes, 0o600); err != nil {
			fail("写入私钥失败: " + err.Error())
		}
		fmt.Println("私钥已写入:", *keyPath, "（请离线保管，不要提交到仓库）")
		fmt.Println("公钥（配置到服务端 DOCVAULT_LICENSE_PUBKEY）：")
		fmt.Println(base64.StdEncoding.EncodeToString(pubKey))
		return
	}

	priv, err := loadKey(*keyPath)
	if err != nil {
		fail(err.Error())
	}

	if *verify != "" {
		pubKey := priv.Public().(ed25519.PublicKey)
		if *pub != "" {
			pubKey, err = license.ParsePublicKey(*pub)
			if err != nil {
				fail(err.Error())
			}
		}
		p, err := license.Verify(pubKey, *verify)
		if err != nil {
			fmt.Println("校验失败:", err.Error())
			os.Exit(1)
		}
		pretty, _ := json.MarshalIndent(p, "", "  ")
		fmt.Println("校验通过:")
		fmt.Println(string(pretty))
		return
	}

	if strings.TrimSpace(*customer) == "" {
		fail("必须用 -customer 指定客户名称")
	}

	id := *licenseID
	if id == "" {
		id = "DV-" + time.Now().Format("20060102") + "-" + randomTag(4)
	}

	p := license.Payload{
		V:          license.Version,
		LicenseID:  id,
		Customer:   strings.TrimSpace(*customer),
		InstanceID: strings.TrimSpace(*instance),
		Edition:    strings.TrimSpace(*edition),
		// 本地版是全功能：用 "*" 表达，而不是逐项列举 ——
		// 逐项列举意味着"以后新增的能力老许可证都没有"，客户会莫名其妙少功能。
		Capabilities: []string{"*"},
		Seats:        *seats,
		IssuedAt:     time.Now().Format(time.RFC3339),
		Note:         strings.TrimSpace(*note),
	}
	if *expires != "" {
		t, perr := time.Parse("2006-01-02", *expires)
		if perr != nil {
			fail("-expires 需为 YYYY-MM-DD")
		}
		// 到期日的语义是"当天仍然有效"，所以取当天 23:59:59。
		p.ExpiresAt = t.Add(24*time.Hour - time.Second).Format(time.RFC3339)
	}

	blob, err := sign(priv, p)
	if err != nil {
		fail(err.Error())
	}

	if *out != "" {
		if err := os.WriteFile(*out, []byte(blob+"\n"), 0o600); err != nil {
			fail("写入失败: " + err.Error())
		}
		fmt.Println("已写入:", *out)
		fmt.Println("许可证号:", p.LicenseID, "客户:", p.Customer)
		return
	}
	fmt.Println(blob)
}

func sign(priv ed25519.PrivateKey, p license.Payload) (string, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, raw)
	// 用 RawURL 编码：整串要能安全地粘进邮件、工单、URL 参数。
	return base64.RawURLEncoding.EncodeToString(raw) + "." +
		base64.RawURLEncoding.EncodeToString(sig), nil
}

func loadKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取私钥失败: %w", err)
	}
	// 权限检查：组/其他用户可读的私钥，等同于泄露。
	//
	// 只在类 Unix 上强制：Windows 没有 POSIX 权限位，os.WriteFile(0600) 读回来
	// 仍是 0666，硬性检查会让这条命令在 Windows 上完全不可用（而签发往往就在这里做）。
	// Windows 上改为提示，靠目录 ACL 控制。
	if runtime.GOOS != "windows" {
		if fi, serr := os.Stat(path); serr == nil && fi.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("私钥文件权限过宽（%04o），请执行 chmod 600 %s",
				fi.Mode().Perm(), path)
		}
	} else if fi, serr := os.Stat(path); serr == nil && fi.Mode().Perm()&0o077 != 0 {
		fmt.Fprintln(os.Stderr, "提示: 请确认该文件所在目录的访问权限，私钥泄露等于所有客户许可证都可被伪造")
	}
	priv, err := parsePKCS8(data)
	if err != nil {
		return nil, fmt.Errorf("解析私钥失败: %w", err)
	}
	return priv, nil
}

func randomTag(n int) string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "0000"
	}
	out := make([]byte, n)
	for i, b := range buf {
		out[i] = alphabet[int(b)%len(alphabet)]
	}
	return string(out)
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "错误:", msg)
	os.Exit(1)
}
