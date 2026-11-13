// 增量 SHA-256。
//
// 为什么不用 crypto.subtle.digest：
//   它要求一次性拿到完整 ArrayBuffer。1GB 文件就是 1GB 连续内存，
//   手机上直接崩，桌面也会明显卡顿——而"断点续传"的典型场景正是大文件。
//
// 为什么不用第三方库：
//   只为一个哈希引入依赖，会让前端多一个需要审计的供应链点。
//   算法本身是公开标准且稳定，实现 100 行，配 node:crypto 对比测试足够。
//
// 用法：
//   const h = new Sha256()
//   h.update(buf) ...  h.digestHex()
// 或用 sha256File() 直接对流式读取文件。

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
])

const rotr = (x: number, n: number) => (x >>> n) | (x << (32 - n))

export class Sha256 {
  private h = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ])
  private buf = new Uint8Array(64)
  private bufLen = 0
  private w = new Uint32Array(64)
  private byteLen = 0
  private finished = false

  update(data: Uint8Array): this {
    if (this.finished) throw new Error('Sha256: digest 后再 update')
    this.byteLen += data.length
    let i = 0

    // 先填满上次剩下的缓冲
    if (this.bufLen > 0) {
      const need = 64 - this.bufLen
      const take = Math.min(need, data.length)
      this.buf.set(data.subarray(0, take), this.bufLen)
      this.bufLen += take
      i = take
      if (this.bufLen === 64) {
        this.compress(this.buf, 0)
        this.bufLen = 0
      }
    }

    // 整块直接压缩，不复制
    while (i + 64 <= data.length) {
      this.compress(data, i)
      i += 64
    }

    // 尾巴留到下次
    if (i < data.length) {
      this.buf.set(data.subarray(i), 0)
      this.bufLen = data.length - i
    }
    return this
  }

  digestHex(): string {
    if (this.finished) throw new Error('Sha256: digest 只能调用一次')
    this.finished = true

    // 补位：0x80，再补 0 到 56 字节，最后 8 字节写比特长度（大端）
    const pad = new Uint8Array(this.bufLen < 56 ? 64 : 128)
    pad.set(this.buf.subarray(0, this.bufLen), 0)
    pad[this.bufLen] = 0x80

    // 位长度用 BigInt：超过 2^32 字节的文件（4GB）用 32 位会溢出
    const bits = BigInt(this.byteLen) * 8n
    const at = pad.length - 8
    for (let i = 7; i >= 0; i--) {
      pad[at + i] = Number(bits >> BigInt((7 - i) * 8) & 0xffn)
    }
    this.compress(pad, 0)
    if (pad.length === 128) this.compress(pad, 64)

    let out = ''
    for (let i = 0; i < 8; i++) out += this.h[i].toString(16).padStart(8, '0')
    return out
  }

  private compress(b: Uint8Array, off: number) {
    const w = this.w
    for (let i = 0; i < 16; i++) {
      const j = off + i * 4
      w[i] = ((b[j] << 24) | (b[j + 1] << 16) | (b[j + 2] << 8) | b[j + 3]) >>> 0
    }
    for (let i = 16; i < 64; i++) {
      const s0 = (rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3)) >>> 0
      const s1 = (rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10)) >>> 0
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0
    }

    let a = this.h[0], bb = this.h[1], c = this.h[2], d = this.h[3]
    let e = this.h[4], f = this.h[5], g = this.h[6], hh = this.h[7]

    for (let i = 0; i < 64; i++) {
      const S1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0
      const ch = ((e & f) ^ (~e & g)) >>> 0
      const t1 = (hh + S1 + ch + K[i] + w[i]) >>> 0
      const S0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0
      const maj = ((a & bb) ^ (a & c) ^ (bb & c)) >>> 0
      const t2 = (S0 + maj) >>> 0

      hh = g; g = f; f = e
      e = (d + t1) >>> 0
      d = c; c = bb; bb = a
      a = (t1 + t2) >>> 0
    }

    this.h[0] = (this.h[0] + a) >>> 0
    this.h[1] = (this.h[1] + bb) >>> 0
    this.h[2] = (this.h[2] + c) >>> 0
    this.h[3] = (this.h[3] + d) >>> 0
    this.h[4] = (this.h[4] + e) >>> 0
    this.h[5] = (this.h[5] + f) >>> 0
    this.h[6] = (this.h[6] + g) >>> 0
    this.h[7] = (this.h[7] + hh) >>> 0
  }
}

/**
 * 流式计算文件哈希：按块读、按块算，内存占用与文件大小无关。
 * onProgress 拿到 0..1 的比例（用于"校验中"进度）。
 */
export async function sha256File(
  file: Blob,
  onProgress?: (pct: number) => void,
  signal?: AbortSignal,
  readSize = 4 << 20,
): Promise<string> {
  const h = new Sha256()
  const total = file.size
  let done = 0
  while (done < total) {
    // 每块检查一次取消：5GB 文件算完要好几分钟，不能等它算完才响应"取消"
    if (signal?.aborted) throw new Error('已取消')
    const end = Math.min(done + readSize, total)
    const buf = new Uint8Array(await file.slice(done, end).arrayBuffer())
    h.update(buf)
    done = end
    onProgress?.(total === 0 ? 1 : done / total)
    // 让出主线程：否则大文件会把页面冻住，连"取消"都点不动
    await new Promise((r) => setTimeout(r, 0))
  }
  onProgress?.(1)
  return h.digestHex()
}
