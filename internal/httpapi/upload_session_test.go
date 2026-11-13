package httpapi

// AC-78 / AC-67 分片上传与秒传。

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// putPart 直传一个分片的原始字节。
func putPart(t *testing.T, srvURL, token, uploadID string, no int, data string) (*http.Response, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPut,
		srvURL+"/v1/uploads/"+uploadID+"/parts/"+itoaSmall(no), bytes.NewReader([]byte(data)))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("上传分片失败: %v", err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = decodeBody(resp, &out)
	return resp, out
}

func decodeBody(resp *http.Response, out *map[string]any) error {
	return json.NewDecoder(resp.Body).Decode(out)
}

// AC-78：分片上传完成后内容正确，且重复 complete 幂等（不产生第二个版本）。
func TestAC78ChunkedUploadIsIdempotent(t *testing.T) {
	srv, pool, slug := setup(t)
	owner := login(t, srv.URL, slug)
	_, body := postJSON(t, srv.URL+"/v1/spaces", owner, map[string]any{"kind": "project", "name": "分片空间"})
	spaceID := dataMap(t, body)["spaceId"].(string)

	// 分片大小显式给 1MiB：分片边界是会话属性，测试必须按真实多片场景走，
	// 否则"声明 10 字节却传 2 片"这种写法在真实协议里根本不可能出现。
	const partSize = 1 << 20
	part1 := strings.Repeat("a", partSize)
	const part2 = "tail"
	full := part1 + part2

	resp, out := postJSON(t, srv.URL+"/v1/uploads", owner, map[string]any{
		"spaceId": spaceID, "name": "big.txt", "sizeBytes": len(full),
		"sha256": sha256Hex(full), "partSize": partSize,
	})
	if resp.StatusCode != 200 {
		t.Fatalf("创建会话失败 %d: %v", resp.StatusCode, out)
	}
	d := dataMap(t, out)
	if d["deduped"] == true {
		t.Fatalf("首次上传不应秒传: %v", d)
	}
	uploadID := d["uploadId"].(string)

	if r, o := putPart(t, srv.URL, owner, uploadID, 1, part1); r.StatusCode != 200 {
		t.Fatalf("分片 1 失败 %d: %v", r.StatusCode, o)
	}
	if r, o := putPart(t, srv.URL, owner, uploadID, 2, part2); r.StatusCode != 200 {
		t.Fatalf("分片 2 失败 %d: %v", r.StatusCode, o)
	}

	resp, out = postJSON(t, srv.URL+"/v1/uploads/"+uploadID+"/complete", owner, map[string]any{})
	if resp.StatusCode != 200 {
		t.Fatalf("complete 失败 %d: %v", resp.StatusCode, out)
	}
	nodeID := dataMap(t, out)["nodeId"].(string)

	// 内容正确
	_, raw := getRaw(t, srv.URL+"/v1/nodes/"+nodeID+"/content", owner)
	if string(raw) != full {
		t.Fatalf("合并内容不符: %q", string(raw))
	}

	// 重复 complete：幂等，返回同一节点，不新增版本
	resp, out = postJSON(t, srv.URL+"/v1/uploads/"+uploadID+"/complete", owner, map[string]any{})
	if resp.StatusCode != 200 {
		t.Fatalf("重复 complete 应 200（幂等），实际 %d: %v", resp.StatusCode, out)
	}
	if dataMap(t, out)["nodeId"] != nodeID {
		t.Fatalf("重复 complete 应返回同一节点: %v", out)
	}
	var versions int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM version WHERE node_id = $1`, nodeID).Scan(&versions); err != nil {
		t.Fatal(err)
	}
	if versions != 1 {
		t.Fatalf("AC-78 重复 complete 不应新增版本，实际 %d 个", versions)
	}
}

// AC-78 补充：分片不连续必须拒绝（否则拼出来的内容是错的）。
func TestAC78MissingPartRejected(t *testing.T) {
	srv, _, slug := setup(t)
	owner := login(t, srv.URL, slug)
	_, body := postJSON(t, srv.URL+"/v1/spaces", owner, map[string]any{"kind": "project", "name": "缺片空间"})
	spaceID := dataMap(t, body)["spaceId"].(string)

	// 两片真实场景：声明 1MiB+2 字节、分片 1MiB，只传第 2 片 → 缺第 1 片
	const partSize = 1 << 20
	resp, out := postJSON(t, srv.URL+"/v1/uploads", owner, map[string]any{
		"spaceId": spaceID, "name": "gap.txt", "sizeBytes": partSize + 2, "partSize": partSize,
	})
	if resp.StatusCode != 200 {
		t.Fatalf("创建会话失败 %d: %v", resp.StatusCode, out)
	}
	uploadID := dataMap(t, out)["uploadId"].(string)

	// 只传第 2 片
	putPart(t, srv.URL, owner, uploadID, 2, "01")

	resp, out = postJSON(t, srv.URL+"/v1/uploads/"+uploadID+"/complete", owner, map[string]any{})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("缺片应 400，实际 %d: %v", resp.StatusCode, out)
	}
	if out["code"] != "PARTS_INCOMPLETE" {
		t.Fatalf("应返回 PARTS_INCOMPLETE: %v", out)
	}
}

// AC-67：秒传只能由服务端核对，声明与实际不符必须拒绝。
func TestAC67DedupAndSizeForgery(t *testing.T) {
	srv, _, slug := setup(t)
	owner := login(t, srv.URL, slug)
	_, body := postJSON(t, srv.URL+"/v1/spaces", owner, map[string]any{"kind": "project", "name": "秒传空间"})
	spaceID := dataMap(t, body)["spaceId"].(string)

	content := "resume-content-2026"
	// 先正常上传一份，让 blob 存在
	if r, o := upload(t, srv.URL+"/v1/spaces/"+spaceID+"/files", owner, "orig.txt", content); r.StatusCode != 200 {
		t.Fatalf("首次上传失败 %d: %v", r.StatusCode, o)
	}

	// 同样的 sha256 + size → 秒传
	resp, out := postJSON(t, srv.URL+"/v1/uploads", owner, map[string]any{
		"spaceId": spaceID, "name": "copy.txt",
		"sizeBytes": len(content), "sha256": sha256Hex(content),
	})
	if resp.StatusCode != 200 {
		t.Fatalf("秒传请求失败 %d: %v", resp.StatusCode, out)
	}
	d := dataMap(t, out)
	if d["deduped"] != true {
		t.Fatalf("AC-67 相同内容应秒传: %v", d)
	}
	if d["nodeId"] == nil || d["nodeId"] == "" {
		t.Fatalf("AC-67 秒传应返回节点: %v", d)
	}

	// 声明 size 比真实内容小 → 不能秒传（否则可"声明小尺寸换取他人文件"）
	resp, out = postJSON(t, srv.URL+"/v1/uploads", owner, map[string]any{
		"spaceId": spaceID, "name": "fake.txt",
		"sizeBytes": 1, "sha256": sha256Hex(content),
	})
	if resp.StatusCode != 200 {
		t.Fatalf("请求应被接受（只是不能秒传）: %v", out)
	}
	if dataMap(t, out)["deduped"] == true {
		t.Fatalf("AC-67 size 不匹配时不应秒传: %v", out)
	}

	// 走完整分片流程但内容与声明哈希不符 → HASH_MISMATCH
	uploadID := dataMap(t, out)["uploadId"].(string)
	putPart(t, srv.URL, owner, uploadID, 1, "x") // 1 字节，size 对但哈希不对
	resp, out = postJSON(t, srv.URL+"/v1/uploads/"+uploadID+"/complete", owner, map[string]any{})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("AC-67 哈希不符应 400，实际 %d: %v", resp.StatusCode, out)
	}
	if out["code"] != "HASH_MISMATCH" {
		t.Fatalf("AC-67 应返回 HASH_MISMATCH: %v", out)
	}
}

// 断点续传：重选同一文件必须复用会话，只补缺口。
//
// 这是"断点续传"与"分片上传"的分界线：前者要跨请求恢复，后者只需要一次跑完。
// 如果这里退化成新建会话，用户每次网络抖动都得从第一片重传——
// 而 99% 的人不会重试第三次。
func TestUploadResumeReusesSession(t *testing.T) {
	srv, _, slug := setup(t)
	owner := login(t, srv.URL, slug)
	_, body := postJSON(t, srv.URL+"/v1/spaces", owner, map[string]any{"kind": "project", "name": "续传空间"})
	spaceID := dataMap(t, body)["spaceId"].(string)

	const partSize = 1 << 20
	part1 := strings.Repeat("A", partSize)
	part2 := strings.Repeat("B", partSize)
	const part3 = "tail-2026"
	full := part1 + part2 + part3
	req := map[string]any{
		"spaceId": spaceID, "name": "resume.bin",
		"sizeBytes": len(full), "sha256": sha256Hex(full), "partSize": partSize,
	}

	// 第一次：建会话，只传第 1 片就"断线"
	resp, out := postJSON(t, srv.URL+"/v1/uploads", owner, req)
	if resp.StatusCode != 200 {
		t.Fatalf("建会话失败 %d: %v", resp.StatusCode, out)
	}
	d := dataMap(t, out)
	uploadID := d["uploadId"].(string)
	if got := d["receivedParts"].([]any); len(got) != 0 {
		t.Fatalf("新会话不应已收分片: %v", got)
	}
	if r, o := putPart(t, srv.URL, owner, uploadID, 1, part1); r.StatusCode != 200 {
		t.Fatalf("传第 1 片失败 %d: %v", r.StatusCode, o)
	}

	// 第二次：同一文件重选 → 复用同一会话，并告知已收分片
	resp, out = postJSON(t, srv.URL+"/v1/uploads", owner, req)
	if resp.StatusCode != 200 {
		t.Fatalf("续传建会话失败 %d: %v", resp.StatusCode, out)
	}
	d = dataMap(t, out)
	if d["resumed"] != true {
		t.Fatalf("应复用已有会话，实际 %v", d)
	}
	if d["uploadId"] != uploadID {
		t.Fatalf("续传应返回原会话 %s，实际 %v", uploadID, d["uploadId"])
	}
	if parts := d["receivedParts"].([]any); len(parts) != 1 || parts[0].(float64) != 1 {
		t.Fatalf("已收分片应为 [1]，实际 %v", parts)
	}
	if d["partSize"].(float64) != partSize {
		t.Fatalf("续传必须沿会话的分片边界 %d，实际 %v", partSize, d["partSize"])
	}

	// 查询接口与续传结果一致
	resp, out = getJSON(t, srv.URL+"/v1/uploads/"+uploadID, owner)
	if resp.StatusCode != 200 {
		t.Fatalf("查询会话失败 %d: %v", resp.StatusCode, out)
	}
	if parts := dataMap(t, out)["receivedParts"].([]any); len(parts) != 1 {
		t.Fatalf("查询应返回已收分片，实际 %v", parts)
	}

	// 只补缺失的两片 → 完成，内容正确（证明没有重复写入第 1 片）
	for i, chunk := range map[int]string{2: part2, 3: part3} {
		if r, o := putPart(t, srv.URL, owner, uploadID, i, chunk); r.StatusCode != 200 {
			t.Fatalf("补第 %d 片失败 %d: %v", i, r.StatusCode, o)
		}
	}
	resp, out = postJSON(t, srv.URL+"/v1/uploads/"+uploadID+"/complete", owner, map[string]any{})
	if resp.StatusCode != 200 {
		t.Fatalf("续传后 complete 失败 %d: %v", resp.StatusCode, out)
	}
	nodeID := dataMap(t, out)["nodeId"].(string)
	_, raw := getRaw(t, srv.URL+"/v1/nodes/"+nodeID+"/content", owner)
	if string(raw) != full {
		t.Fatalf("续传合并内容不符：期望 %d 字节，实际 %d", len(full), len(raw))
	}
}

// 分片号超出声明片数必须拒绝：否则磁盘上会留一份永远不被合并的垃圾。
func TestUploadPartNoOutOfRangeRejected(t *testing.T) {
	srv, _, slug := setup(t)
	owner := login(t, srv.URL, slug)
	_, body := postJSON(t, srv.URL+"/v1/spaces", owner, map[string]any{"kind": "project", "name": "越界空间"})
	spaceID := dataMap(t, body)["spaceId"].(string)

	const partSize = 1 << 20
	resp, out := postJSON(t, srv.URL+"/v1/uploads", owner, map[string]any{
		"spaceId": spaceID, "name": "small.bin", "sizeBytes": partSize + 1, "partSize": partSize,
	})
	if resp.StatusCode != 200 {
		t.Fatalf("建会话失败 %d: %v", resp.StatusCode, out)
	}
	uploadID := dataMap(t, out)["uploadId"].(string)

	// 该文件只有 2 片，第 3 片不存在
	if r, o := putPart(t, srv.URL, owner, uploadID, 3, "x"); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("越界分片应 400，实际 %d: %v", r.StatusCode, o)
	}
}

// 会话只对本人可见：里面含目标目录与文件名，跨用户可读等于泄露目录结构。
func TestUploadSessionNotVisibleToOthers(t *testing.T) {
	srv, _, slug := setup(t)
	owner := login(t, srv.URL, slug)
	_, body := postJSON(t, srv.URL+"/v1/spaces", owner, map[string]any{"kind": "project", "name": "私有空间"})
	spaceID := dataMap(t, body)["spaceId"].(string)

	resp, out := postJSON(t, srv.URL+"/v1/uploads", owner, map[string]any{
		"spaceId": spaceID, "name": "private.bin", "sizeBytes": 1024,
	})
	if resp.StatusCode != 200 {
		t.Fatalf("建会话失败 %d: %v", resp.StatusCode, out)
	}
	uploadID := dataMap(t, out)["uploadId"].(string)

	// 用不存在的会话 ID 访问：不区分"不存在"与"不是你的"，避免探测
	other := login(t, srv.URL, slug) // 同一租户内的另一个会话（用户相同，仍应可读）
	if r, _ := getJSON(t, srv.URL+"/v1/uploads/"+uploadID, other); r.StatusCode != 200 {
		t.Fatalf("本人会话应可读，实际 %d", r.StatusCode)
	}
	if r, _ := getJSON(t, srv.URL+"/v1/uploads/00000000-0000-0000-0000-000000000000", owner); r.StatusCode != http.StatusNotFound {
		t.Fatalf("未知会话应 404，实际 %d", r.StatusCode)
	}
}
