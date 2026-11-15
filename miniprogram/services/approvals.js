// 审批：待我审批的分享申请 + 通过/驳回。
//
// 判定不在前端：谁能批、能不能批由服务端（share.Approve + ManageACL）决定，
// 这里只负责把服务端的结论展示出来。
const { request } = require('../utils/request')

function pending() {
  return request({ path: '/v1/shares/pending' }).then(function (d) {
    return d.items || []
  })
}

// decide 通过或驳回。服务端接口只收一个 approve 布尔，没有"意见"字段——
// 驳回原因在当前数据模型里不落库，前端不要伪造一个看似会保存的输入框。
function decide(id, approve) {
  return request({
    path: '/v1/shares/' + id + '/approve',
    method: 'POST',
    data: { approve: !!approve }
  })
}

module.exports = { pending, decide }
