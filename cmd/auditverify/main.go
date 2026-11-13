// Command auditverify 离线校验审计证据包。
//
// 为什么必须是独立程序：
//   - 校验器不能复用被审计系统自己的代码路径（否则同一个 bug 会把"错"验成"对"）；
//   - 客户/审计方需要在没有数据库、没有服务端的机器上复算。
//
// 用法：
//
//	auditverify -bundle evidence.json
//	auditverify -bundle evidence.json -secret <锚点密钥>
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"
)

// 与内部 record 结构严格对应：字段顺序与 json tag 都不能改，
// 否则复算的字节不一致，会把正常数据判成篡改。
type chainRecord struct {
	Seq       int64  `json:"seq"`
	ActorID   string `json:"actor_id"`
	ActorType string `json:"actor_type"`
	Action    string `json:"action"`
	ObjType   string `json:"object_type"`
	ObjID     string `json:"object_id"`
	Result    string `json:"result"`
	Detail    any    `json:"detail"`
	IP        string `json:"ip"`
	RequestID string `json:"request_id"`
	CreatedAt string `json:"created_at"`
}

type bundleEvent struct {
	Seq        int64          `json:"seq"`
	ActorID    string         `json:"actorId"`
	ActorType  string         `json:"actorType"`
	Action     string         `json:"action"`
	ObjectType string         `json:"objectType"`
	ObjectID   string         `json:"objectId"`
	Result     string         `json:"result"`
	Detail     map[string]any `json:"detail"`
	IP         string         `json:"ip"`
	RequestID  string         `json:"requestId"`
	PrevHash   string         `json:"prevHash"`
	Hash       string         `json:"hash"`
	CreatedAt  string         `json:"createdAt"`
}

type anchorRow struct {
	TenantID   string `json:"TenantID"`
	Day        string `json:"Day"`
	SeqFrom    int64  `json:"SeqFrom"`
	SeqTo      int64  `json:"SeqTo"`
	Count      int    `json:"Count"`
	MerkleRoot string `json:"MerkleRoot"`
	ChainHead  string `json:"ChainHead"`
	Signature  string `json:"Signature"`
	Algorithm  string `json:"Algorithm"`
}

type bundle struct {
	Format     string        `json:"format"`
	TenantID   string        `json:"tenantId"`
	From       string        `json:"from"`
	To         string        `json:"to"`
	EventCount int           `json:"eventCount"`
	Events     []bundleEvent `json:"events"`
	Anchors    []anchorRow   `json:"anchors"`
}

func main() {
	var (
		path   = flag.String("bundle", "", "证据包 JSON 路径")
		secret = flag.String("secret", "", "锚点 HMAC 密钥（留空则跳过签名校验）")
	)
	flag.Parse()
	if *path == "" {
		fmt.Fprintln(os.Stderr, "必须指定 -bundle")
		os.Exit(2)
	}

	raw, err := os.ReadFile(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取证据包失败: %v\n", err)
		os.Exit(1)
	}
	var b bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		fmt.Fprintf(os.Stderr, "解析证据包失败: %v\n", err)
		os.Exit(1)
	}
	if b.Format != "docvault-evidence-v1" {
		fmt.Fprintf(os.Stderr, "不支持的数据格式: %s\n", b.Format)
		os.Exit(2)
	}

	problems := verifyChain(b.Events)
	problems = append(problems, verifyAnchors(b.Events, b.Anchors, *secret)...)

	if len(problems) > 0 {
		fmt.Printf("校验失败：发现 %d 处问题\n", len(problems))
		for _, p := range problems {
			fmt.Println("  -", p)
		}
		os.Exit(1)
	}
	fmt.Printf("校验通过：%d 条事件，%d 个锚点，链与锚点一致\n", len(b.Events), len(b.Anchors))
}

// verifyChain 复算哈希链。
func verifyChain(events []bundleEvent) []string {
	var problems []string
	sort.Slice(events, func(i, j int) bool { return events[i].Seq < events[j].Seq })

	var prev []byte
	for i, e := range events {
		created, err := time.Parse(time.RFC3339Nano, e.CreatedAt)
		if err != nil {
			problems = append(problems, fmt.Sprintf("seq=%d 时间格式非法: %v", e.Seq, err))
			continue
		}
		detail := any(map[string]any{})
		if e.Detail != nil {
			detail = e.Detail
		}
		body, err := json.Marshal(chainRecord{
			Seq: e.Seq, ActorID: e.ActorID, ActorType: e.ActorType, Action: e.Action,
			ObjType: e.ObjectType, ObjID: e.ObjectID, Result: e.Result, Detail: detail,
			IP: e.IP, RequestID: e.RequestID,
			CreatedAt: created.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano),
		})
		if err != nil {
			problems = append(problems, fmt.Sprintf("seq=%d 序列化失败: %v", e.Seq, err))
			continue
		}
		h := sha256.New()
		h.Write(prev)
		h.Write(body)
		if hex.EncodeToString(h.Sum(nil)) != e.Hash {
			problems = append(problems, fmt.Sprintf("seq=%d 哈希不匹配（内容被改）", e.Seq))
		}
		if e.PrevHash == "" {
			if i != 0 {
				problems = append(problems, fmt.Sprintf("seq=%d 缺少前序哈希", e.Seq))
			}
		} else if e.PrevHash != hex.EncodeToString(prev) {
			problems = append(problems, fmt.Sprintf("seq=%d 前序哈希不匹配（链被重排或删除）", e.Seq))
		}
		prev, _ = hex.DecodeString(e.Hash)
	}
	return problems
}

// verifyAnchors 校验锚点的 Merkle 根、计数与签名。
func verifyAnchors(events []bundleEvent, anchors []anchorRow, secret string) []string {
	var problems []string
	for _, a := range anchors {
		var leaves [][]byte
		var lastHash string
		for _, e := range events {
			if dayOf(e.CreatedAt) != a.Day {
				continue
			}
			h, err := hex.DecodeString(e.Hash)
			if err != nil {
				problems = append(problems, fmt.Sprintf("锚点 %s: 事件哈希非法", a.Day))
				continue
			}
			leaves = append(leaves, h)
			lastHash = e.Hash
		}
		if len(leaves) != a.Count {
			problems = append(problems, fmt.Sprintf("锚点 %s: 事件数不符（锚点 %d，包内 %d）",
				a.Day, a.Count, len(leaves)))
			continue
		}
		root := merkleRoot(leaves)
		if hex.EncodeToString(root) != a.MerkleRoot {
			problems = append(problems, fmt.Sprintf("锚点 %s: Merkle 根不匹配", a.Day))
		}
		if lastHash != a.ChainHead {
			problems = append(problems, fmt.Sprintf("锚点 %s: 链头不匹配", a.Day))
		}
		if secret != "" {
			rootBytes, _ := hex.DecodeString(a.MerkleRoot)
			headBytes, _ := hex.DecodeString(a.ChainHead)
			mac := hmac.New(sha256.New, []byte(secret))
			mac.Write(anchorInput(a.TenantID, a.Day, a.SeqFrom, a.SeqTo, a.Count, rootBytes, headBytes))
			if !hmac.Equal([]byte(hex.EncodeToString(mac.Sum(nil))), []byte(a.Signature)) {
				problems = append(problems, fmt.Sprintf("锚点 %s: 签名无效", a.Day))
			}
		}
	}
	return problems
}

func merkleRoot(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		return nil
	}
	level := make([][]byte, len(leaves))
	copy(level, leaves)
	for len(level) > 1 {
		if len(level)%2 == 1 {
			level = append(level, level[len(level)-1])
		}
		next := make([][]byte, 0, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			h := sha256.New()
			h.Write(level[i])
			h.Write(level[i+1])
			next = append(next, h.Sum(nil))
		}
		level = next
	}
	return level[0]
}

// anchorInput 必须与服务端逐字节一致（含分隔符与整数编码方式）。
func anchorInput(tenantID, day string, seqFrom, seqTo int64, count int, merkle, head []byte) []byte {
	var buf []byte
	buf = append(buf, []byte("docvault-anchor-v1")...)
	buf = append(buf, 0)
	buf = append(buf, []byte(tenantID)...)
	buf = append(buf, 0)
	buf = append(buf, []byte(day)...)
	appendUint64 := func(v uint64) {
		var b [8]byte
		for i := 7; i >= 0; i-- {
			b[i] = byte(v)
			v >>= 8
		}
		buf = append(buf, b[:]...)
	}
	appendUint64(uint64(seqFrom))
	appendUint64(uint64(seqTo))
	appendUint64(uint64(count))
	buf = append(buf, merkle...)
	buf = append(buf, head...)
	return buf
}

func dayOf(rfc3339 string) string {
	t, err := time.Parse(time.RFC3339Nano, rfc3339)
	if err != nil {
		return ""
	}
	return t.UTC().Format("2006-01-02")
}
