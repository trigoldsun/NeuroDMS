const fs=require('fs')
const p='web/src/api.ts'
let s=fs.readFileSync(p,'utf8')
const anchor="export function getShareVisits(id: string): Promise<ShareVisits> {\n  return api<ShareVisits>(`/v1/shares/${encodeURIComponent(id)}/visits`)\n}\n"
if(!s.includes(anchor)) throw new Error('anchor missing')
const block=`
// revokeShare 撤销一条自己创建的外链：链接立即失效，已签发的票据同时吊销。
//
// 为什么必须有这个入口：链接发错了（发给了错的人、带错了文件）过去只能等过期，
// 而外链默认是长期有效。撤销接口一直在，缺的是界面入口。
export async function revokeShare(id: string): Promise<void> {
  await api<unknown>(\`/v1/shares/\${encodeURIComponent(id)}/revoke\`, { method: 'POST' })
}
`
s=s.replace(anchor, anchor+block)
fs.writeFileSync(p,s)
console.log('api.ts ok')

const q='web/src/pages/MyShares.tsx'
let t=fs.readFileSync(q,'utf8')
const before=(t.match(/s\.objectName/g)||[]).length
t=t.split('s.objectName').join('s.name')
fs.writeFileSync(q,t)
console.log('MyShares objectName refs fixed:', before)
