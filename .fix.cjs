const fs=require('fs')

// ---- api.ts：把误插进函数体的块移出来 ----
const p='web/src/api.ts'
let s=fs.readFileSync(p,'utf8')
const startMark='\n// revokeShare 撤销一条自己创建的外链'
const i=s.indexOf(startMark)
if(i<0) throw new Error('block start missing')
const fnIdx=s.indexOf('export async function revokeShare', i)
const fnEnd=s.indexOf('\n}', fnIdx)   // 函数体结束的 "}"
const block=s.slice(i, fnEnd+2)       // 含开头的 \n 与结尾的 \n}
s=s.slice(0,i)+s.slice(fnEnd+2)
// 现在应当剩 .../visits`) \n } \n } —— 修正可能多出来的 "}"
s=s.replace("return api<ShareVisits>(`/v1/shares/${encodeURIComponent(id)}/visits`)\n\n}\n","return api<ShareVisits>(`/v1/shares/${encodeURIComponent(id)}/visits`)\n}\n")
s=s.replace("return api<ShareVisits>(`/v1/shares/${encodeURIComponent(id)}/visits`)\n}\n}\n","return api<ShareVisits>(`/v1/shares/${encodeURIComponent(id)}/visits`)\n}\n")

// 插到 getShareVisits 之后
const gv=s.indexOf('export function getShareVisits')
const gvEnd=s.indexOf('\n}\n', gv)
if(gv<0||gvEnd<0) throw new Error('getShareVisits anchor')
s=s.slice(0, gvEnd+3)+block+s.slice(gvEnd+3)
fs.writeFileSync(p,s)
console.log('api.ts fixed')

// ---- MyShares.tsx：字段名 ----
const q='web/src/pages/MyShares.tsx'
let t=fs.readFileSync(q,'utf8')
const n=t.split('s.objectName').length-1
t=t.split('s.objectName').split('s.name').join('s.name')
t=t.split('s.objectName').join('s.name')
fs.writeFileSync(q,t)
console.log('MyShares field refs fixed:', n)
