/* 流程图数据：坐标为 (列 c, 行 r)，由 flow.js 排版。
   t: act 人做的动作 / sys 系统自动 / dec 判定 / bad 失败终止 / warn 待定 / adv 建议终止 / pill 起止
   via: bus = 从右侧总线绕行，避免长连线穿过方框 */

window.FLOWS = {

  'upload': {
    id: 'upload', fig: '图 1-1',
    title: '上传一份文件：先判格式，再决定要不要分片',
    hint: '序号与下方步骤表一致',
    nodes: [
      { id: 'a', t: 'pill', c: 0, r: 0, label: '进入目标目录，选择或拖入文件' },
      { id: 'b', t: 'dec', c: 0, r: 1, label: '格式在租户白名单内？', sub: '选完文件的一瞬间就判' },
      { id: 'b1', t: 'bad', c: 1, r: 1, label: '标红提示，不产生任何上传' },
      { id: 'c', t: 'dec', c: 0, r: 2, label: '单个文件大于 2MB？' },
      { id: 'c1', t: 'sys', c: 1, r: 2, label: '一次性直传' },
      { id: 'd', t: 'sys', c: 0, r: 3, label: '计算 SHA-256 校验值', sub: '显示「校验 x%」，无网络流量' },
      { id: 'e', t: 'dec', c: 0, r: 4, label: '服务端已有相同内容？' },
      { id: 'e1', t: 'pill', k: 'ok', c: 1, r: 4, label: '秒传完成，不重复占容量' },
      { id: 'f', t: 'sys', c: 0, r: 5, label: '按 1MB 分片上传', sub: '显示 已传 x.x MB · n/m 片' },
      { id: 'g', t: 'dec', c: 0, r: 6, label: '中途断网或关掉页面？' },
      { id: 'g1', t: 'act', c: 1, r: 6, label: '重选同一个文件续传', sub: '会话留 24 小时，只补缺片', n: 6 },
      { id: 'h', t: 'sys', c: 0, r: 7, label: '合并校验，生成新版本' },
      { id: 'i', t: 'pill', k: 'ok', c: 0, r: 8, label: '上传完成，列表刷新' }
    ],
    edges: [
      { f: 'a', t: 'b' }, { f: 'b', t: 'b1', l: '否' }, { f: 'b', t: 'c', l: '是' },
      { f: 'c', t: 'c1', l: '否' }, { f: 'c', t: 'd', l: '是' }, { f: 'c1', t: 'h', via: 'bus' },
      { f: 'd', t: 'e' }, { f: 'e', t: 'e1', l: '是' }, { f: 'e', t: 'f', l: '否' },
      { f: 'f', t: 'g' }, { f: 'g', t: 'g1', l: '是' }, { f: 'g', t: 'h', l: '否' },
      { f: 'g1', t: 'h', via: 'bus' }, { f: 'h', t: 'i' }
    ],
    foot: '「校验 x%」阶段没有网络流量，不是卡住；大文件可能要几十秒。'
  },

  'search': {
    id: 'search', fig: '图 2-1',
    title: '检索：结果不是"库里有什么"，而是"你能看到什么"',
    nodes: [
      { id: 'a', t: 'pill', c: 0, r: 0, label: '在顶部搜索框输入文件名片段' },
      { id: 'b', t: 'sys', c: 0, r: 1, label: '在租户内检索文件名', sub: '只搜文件名，不搜正文' },
      { id: 'c', t: 'sys', c: 0, r: 2, label: '逐条做可见性判定', sub: 'display 权限 · 密级 · 显式拒绝' },
      { id: 'd', t: 'dec', c: 0, r: 3, label: '有权限且密级够？' },
      { id: 'd1', t: 'bad', c: 1, r: 3, label: '从结果中剔除，不提示原因' },
      { id: 'e', t: 'sys', c: 0, r: 4, label: '返回：名称 · 空间 · 大小 · 时间' },
      { id: 'f', t: 'dec', c: 0, r: 5, label: '结果为空？' },
      { id: 'f1', t: 'adv', c: 1, r: 5, label: '按「权限解释」的结论找对应的人', sub: '可能是真没权限，不是文件丢了' },
      { id: 'g', t: 'act', c: 0, r: 6, label: '点文件名＝预览；点空间名＝回根目录', sub: '文件名新开页签，不打断当前列表', n: 3 },
      { id: 'h', t: 'pill', k: 'ok', c: 0, r: 7, label: '看到目标文件' }
    ],
    edges: [
      { f: 'a', t: 'b' }, { f: 'b', t: 'c' }, { f: 'c', t: 'd' },
      { f: 'd', t: 'd1', l: '否' }, { f: 'd', t: 'e', l: '是' },
      { f: 'e', t: 'f' }, { f: 'f', t: 'f1', l: '是' }, { f: 'f', t: 'g', l: '否' }, { f: 'g', t: 'h' }
    ]
  },

  'grant': {
    id: 'grant', fig: '图 3-1',
    title: '授权：给谁、给到哪一档、要不要留例外',
    nodes: [
      { id: 'a', t: 'pill', c: 0, r: 0, label: '对象所有者打开授权抽屉' },
      { id: 'b', t: 'act', c: 0, r: 1, w: 252, label: '选主体：用户、部门、角色、组', sub: '给组授一次，胜过给十个人各授一次', n: 1 },
      { id: 'c', t: 'act', c: 0, r: 2, label: '选档位，设到期时间', sub: '临时协作务必设到期', n: 2 },
      { id: 'd', t: 'dec', c: 0, r: 3, label: '档位高于自己的封顶？' },
      { id: 'd1', t: 'bad', c: 1, r: 3, label: '拒绝：CEILING_EXCEEDED', sub: '不能授出比自己更高的权限' },
      { id: 'e', t: 'sys', c: 0, r: 4, label: '写入权限条目，下一次请求即生效', sub: '对方不需要重新登录' },
      { id: 'f', t: 'dec', c: 0, r: 5, label: '要给子目录做例外？' },
      { id: 'f1', t: 'sys', c: 1, r: 5, label: '断开继承：快照祖先条目', sub: '快照不能单独删，要先恢复继承' },
      { id: 'g', t: 'sys', c: 0, r: 6, label: '被授权人刷新页面即可见' },
      { id: 'h', t: 'pill', k: 'ok', c: 0, r: 7, label: '协作开始，可随时撤销单条' }
    ],
    edges: [
      { f: 'a', t: 'b' }, { f: 'b', t: 'c' }, { f: 'c', t: 'd' },
      { f: 'd', t: 'd1', l: '是' }, { f: 'd', t: 'e', l: '否' },
      { f: 'e', t: 'f' }, { f: 'f', t: 'f1', l: '是' }, { f: 'f', t: 'g', l: '否' },
      { f: 'f1', t: 'g', via: 'bus' }, { f: 'g', t: 'h' }
    ]
  },

  'edit': {
    id: 'edit', fig: '图 4-1',
    title: '在线编辑与版本回退：保存永远向前追加',
    nodes: [
      { id: 'a', t: 'pill', c: 0, r: 0, label: '在文件行点「编辑」' },
      { id: 'b', t: 'dec', c: 0, r: 1, label: '有 edit 权限？' },
      { id: 'b1', t: 'bad', c: 1, r: 1, label: '只能预览' },
      { id: 'c', t: 'sys', c: 0, r: 2, label: '签发编辑器配置并登记编辑会话', sub: '10 分钟有效，每 2 分钟心跳' },
      { id: 'd', t: 'act', c: 0, r: 3, label: '在浏览器里编辑', sub: '首次加载 5~15 秒，页面显示已等待秒数', n: 1 },
      { id: 'e', t: 'act', c: 0, r: 4, label: '保存', n: 2 },
      { id: 'f', t: 'sys', c: 0, r: 5, label: '追加新版本（不覆盖），预览缓存失效' },
      { id: 'g', t: 'dec', c: 0, r: 6, label: '需要回退到旧版本？' },
      { id: 'g1', t: 'pill', k: 'ok', c: 1, r: 6, label: '保持现状' },
      { id: 'h', t: 'dec', c: 0, r: 7, label: '还有活跃编辑会话？' },
      { id: 'h1', t: 'bad', c: 1, r: 7, label: '拒绝回退：防止覆盖他人保存', sub: '提示"有 N 个编辑会话进行中"' },
      { id: 'h2', t: 'sys', c: 1, r: 8, label: '回退＝追加一个 restore 版本' },
      { id: 'i', t: 'pill', k: 'ok', c: 1, r: 9, label: '新旧版本都留痕，可再回退' }
    ],
    edges: [
      { f: 'a', t: 'b' }, { f: 'b', t: 'b1', l: '否' }, { f: 'b', t: 'c', l: '是' },
      { f: 'c', t: 'd' }, { f: 'd', t: 'e' }, { f: 'e', t: 'f' }, { f: 'f', t: 'g' },
      { f: 'g', t: 'g1', l: '否' }, { f: 'g', t: 'h', l: '是' },
      { f: 'h', t: 'h1', l: '是' }, { f: 'h', t: 'h2', l: '否' }, { f: 'h2', t: 'i' }
    ],
    foot: '回退不是"删掉后面的版本"：审计要求任何时刻的内容都可追溯，所以回退永远向前追加。'
  },

  'share-create': {
    id: 'share-create', fig: '图 5-1',
    title: '创建外链：三道门 + 选定审批人',
    nodes: [
      { id: 'a', t: 'pill', c: 0, r: 0, label: '选文件 → 分享 → 新建外链' },
      { id: 'b', t: 'dec', c: 0, r: 1, label: '有 share_external（所有者档位）？' },
      { id: 'b1', t: 'bad', c: 1, r: 1, label: '拒绝：需要所有者档位' },
      { id: 'c', t: 'dec', c: 0, r: 2, label: '租户 / 平台已开启对外分享？' },
      { id: 'c1', t: 'bad', c: 1, r: 2, label: '拒绝：FEATURE_DISABLED' },
      { id: 'd', t: 'act', c: 0, r: 3, w: 268, label: '设策略：有效期、口令、下载\n水印、邮箱验证、IP 段', sub: '只读交付就关掉「允许下载」', n: 1 },
      { id: 'e', t: 'dec', c: 0, r: 4, label: '密级 ≥ 租户审批阈值？', sub: '默认「秘密」及以上' },
      { id: 'e1', t: 'act', c: 1, r: 4, label: '列出合格审批人，由发起人选择', sub: '无候选人则禁止创建', n: 2 },
      { id: 'f', t: 'act', c: 1, r: 5, label: '第一层审批人复核', n: 3 },
      { id: 'f1', t: 'bad', c: 2, r: 5, label: '驳回：链接作废，需重建' },
      { id: 'g', t: 'sys', c: 0, r: 7, label: '链接立即可用' },
      { id: 'f2', t: 'dec', c: 1, r: 6, label: '5/6 级且审批人非所有者？' },
      { id: 'f3', t: 'act', c: 1, r: 7, label: '空间所有者确认', sub: '多个所有者时先选一位', n: 4 },
      { id: 'h', t: 'pill', k: 'ok', c: 0, r: 8, label: '等待访客打开' }
    ],
    edges: [
      { f: 'a', t: 'b' }, { f: 'b', t: 'b1', l: '否' }, { f: 'b', t: 'c', l: '是' },
      { f: 'c', t: 'c1', l: '否' }, { f: 'c', t: 'd', l: '是' }, { f: 'd', t: 'e' },
      { f: 'e', t: 'e1', l: '是' }, { f: 'e', t: 'g', l: '否' }, { f: 'e1', t: 'f' },
      { f: 'f', t: 'f1', l: '驳回' }, { f: 'f', t: 'f2', l: '通过' },
      { f: 'f2', t: 'f3', l: '是' }, { f: 'f2', t: 'g', l: '否' },
      { f: 'f3', t: 'g', l: '通过' }, { f: 'g', t: 'h' }
    ]
  },

  'share-visit': {
    id: 'share-visit', fig: '图 5-2',
    title: '访客打开链接：口令、邮箱、票据三道验证',
    nodes: [
      { id: 'a', t: 'pill', c: 0, r: 0, label: '访客打开 /s/{token}' },
      { id: 'b', t: 'dec', c: 0, r: 1, label: '链接可用（未过期/未撤销/已通过）？' },
      { id: 'b1', t: 'bad', c: 1, r: 1, label: '提示已失效或仍在审批中' },
      { id: 'c', t: 'dec', c: 0, r: 2, label: '这条链接设了口令？' },
      { id: 'c1', t: 'sys', c: 1, r: 2, label: '校验口令', sub: '连错 6 次，锁 30 分钟' },
      { id: 'd', t: 'dec', c: 0, r: 3, label: '开启了邮箱验证？' },
      { id: 'd1', t: 'sys', c: 1, r: 3, label: '发验证码并校验', sub: '可限定只允许某些邮箱域名' },
      { id: 'e', t: 'sys', c: 0, r: 4, label: '签发 5 分钟票据', sub: '绑定来源网段：IPv4 /24、IPv6 /64' },
      { id: 'f', t: 'act', c: 0, r: 5, label: '在线查看，或下载（若允许）', sub: '关掉下载时 Office 转 PDF 展示' },
      { id: 'g', t: 'dec', c: 0, r: 6, label: '所有者撤销或链接到期？' },
      { id: 'g1', t: 'bad', c: 1, r: 6, label: '票据立即失效', sub: '已下载到本地的收不回' },
      { id: 'h', t: 'pill', k: 'ok', c: 0, r: 7, label: '访问正常结束' }
    ],
    edges: [
      { f: 'a', t: 'b' }, { f: 'b', t: 'b1', l: '否' }, { f: 'b', t: 'c', l: '是' },
      { f: 'c', t: 'c1', l: '是' }, { f: 'c', t: 'd', l: '否' },
      { f: 'd', t: 'd1', l: '是' }, { f: 'd', t: 'e', l: '否' },
      { f: 'c1', t: 'd' }, { f: 'd1', t: 'e' },
      { f: 'e', t: 'f' }, { f: 'f', t: 'g' }, { f: 'g', t: 'g1', l: '是' }, { f: 'g', t: 'h', l: '否' }
    ]
  },

  'account': {
    id: 'account', fig: '图 7-1',
    title: '三条互不影响的路径：改口令、停用、离职交接',
    hint: '三列并行，不是先后顺序',
    nodes: [
      { id: 'a1', t: 'pill', c: 0, r: 0, label: '用户：修改登录口令' },
      { id: 'a2', t: 'act', c: 0, r: 1, label: '校验旧口令', n: 1 },
      { id: 'a3', t: 'sys', c: 0, r: 2, label: '写入新口令，会话代数 +1' },
      { id: 'a4', t: 'sys', c: 0, r: 3, label: '吊销该账号全部会话' },
      { id: 'a5', t: 'pill', k: 'ok', c: 0, r: 4, label: '所有设备需重新登录' },

      { id: 'b1', t: 'pill', c: 1, r: 0, label: '管理员：停用账号' },
      { id: 'b2', t: 'act', c: 1, r: 1, label: '置为 suspended', n: 3 },
      { id: 'b3', t: 'sys', c: 1, r: 2, label: '吊销会话，令牌 30 秒内失效' },
      { id: 'b4', t: 'adv', c: 1, r: 3, label: '先移交所有权，再停用', sub: '直接停用会让名下文件无人可管' },

      { id: 'c1', t: 'pill', c: 2, r: 0, label: '人员离职' },
      { id: 'c2', t: 'act', c: 2, r: 1, label: '先移交文件所有权', n: 5 },
      { id: 'c3', t: 'act', c: 2, r: 2, label: '再停用账号' },
      { id: 'c4', t: 'pill', k: 'ok', c: 2, r: 3, label: '保留期内审计仍可追溯' }
    ],
    edges: [
      { f: 'a1', t: 'a2' }, { f: 'a2', t: 'a3' }, { f: 'a3', t: 'a4' }, { f: 'a4', t: 'a5' },
      { f: 'b1', t: 'b2' }, { f: 'b2', t: 'b3' }, { f: 'b3', t: 'b4' },
      { f: 'c1', t: 'c2' }, { f: 'c2', t: 'c3' }, { f: 'c3', t: 'c4' }
    ]
  },

  'onboard': {
    id: 'onboard', fig: '图 1-1',
    title: '新成员入职：建号 → 定密级与封顶 → 归档 → 授档位',
    nodes: [
      { id: 'a', t: 'pill', c: 0, r: 0, label: '新成员入职' },
      { id: 'b', t: 'dec', c: 0, r: 1, label: '账号来源？' },
      { id: 'b1', t: 'act', c: 0, r: 2, label: '本地账号：建号 + 初始口令', sub: '口令至少 12 位，走独立通道告知', n: 1 },
      { id: 'b2', t: 'act', c: 1, r: 2, label: '域账号：先配 LDAP，再同步', sub: '或首次登录自动落库' },
      { id: 'c', t: 'sys', c: 0, r: 3, label: '设置密级（可见上限）与封顶（可授出的最高档位）', sub: '密级高于此的文件，给再多权限也看不到' },
      { id: 'd', t: 'dec', c: 0, r: 4, label: '需要管理职能？' },
      { id: 'd1', t: 'act', c: 1, r: 4, label: '授予管理角色', sub: '冲突组合会被运行期拒绝', n: 3 },
      { id: 'e', t: 'act', c: 0, r: 5, label: '加入部门', sub: '父部门授权自动覆盖子部门', n: 4 },
      { id: 'f', t: 'act', c: 0, r: 6, label: '由空间所有者授予档位', sub: '管理员不给内容权限', n: 5 },
      { id: 'g', t: 'pill', k: 'ok', c: 0, r: 7, label: '可以开始使用（建议首登改密）' }
    ],
    edges: [
      { f: 'a', t: 'b' }, { f: 'b', t: 'b1', l: '本地' }, { f: 'b', t: 'b2', l: '域' },
      { f: 'b1', t: 'c' }, { f: 'b2', t: 'c', via: 'bus' },
      { f: 'c', t: 'd' }, { f: 'd', t: 'd1', l: '是' }, { f: 'd', t: 'e', l: '否' },
      { f: 'd1', t: 'e', via: 'bus' }, { f: 'e', t: 'f' }, { f: 'f', t: 'g' }
    ]
  },

  'approve': {
    id: 'approve', fig: '图 6-1',
    title: '谁在审批：指定到人，5/6 级分两层',
    hint: '只有当前环节被指定的人能看到和处理',
    nodes: [
      { id: 'a', t: 'pill', c: 0, r: 0, label: '一条外链进入待审批' },
      { id: 'b', t: 'dec', c: 0, r: 1, label: '你是当前环节指定的审批人？' },
      { id: 'b1', t: 'bad', c: 1, r: 1, label: '列表里看不到，也不能代批' },
      { id: 'c', t: 'dec', c: 0, r: 2, label: '有 manage_acl 且密级 ≥ 文件？' },
      { id: 'd', t: 'dec', c: 0, r: 3, label: '是发起人本人？' },
      { id: 'd1', t: 'bad', c: 1, r: 3, label: 'SELF_APPROVAL_DENIED，禁止自批' },
      { id: 'e', t: 'act', c: 0, r: 4, label: '通过或驳回', n: 1 },
      { id: 'e1', t: 'bad', c: 2, r: 4, label: '驳回：链接作废，需重建' },
      { id: 'f', t: 'dec', c: 0, r: 5, label: '5/6 级且还有第二层？' },
      { id: 'f1', t: 'sys', c: 1, r: 5, label: '转 owner 待办', sub: '链接仍不可用' },
      { id: 'g', t: 'act', c: 1, r: 6, label: '空间所有者确认', n: 2 },
      { id: 'h', t: 'sys', c: 0, r: 8, label: '写审计 share.approve（decision + stage）' },
      { id: 'i', t: 'pill', k: 'ok', c: 0, r: 9, label: '审批闭环，链接可用' }
    ],
    edges: [
      { f: 'a', t: 'b' }, { f: 'b', t: 'b1', l: '否' }, { f: 'b', t: 'c', l: '是' },
      { f: 'c', t: 'b1', l: '否' }, { f: 'c', t: 'd', l: '是' },
      { f: 'd', t: 'd1', l: '是' }, { f: 'd', t: 'e', l: '否' },
      { f: 'e', t: 'e1', l: '驳回' }, { f: 'e', t: 'f', l: '通过' },
      { f: 'f', t: 'f1', l: '是' }, { f: 'f1', t: 'g' }, { f: 'g', t: 'h' },
      { f: 'f', t: 'h', l: '否' }, { f: 'h', t: 'i' }
    ],
    foot: '管理角色不等于审批权；指定审批人也不等于可以代批。'
  },

  'flags': {
    id: 'flags', fig: '图 9-1',
    title: '能力开关求值：覆盖 > 总开关 > 放量，读不到就关',
    nodes: [
      { id: 'a', t: 'pill', c: 0, r: 0, label: '请求判定：某能力是否可用' },
      { id: 'b', t: 'dec', c: 0, r: 1, label: '读到配置了吗？' },
      { id: 'b1', t: 'pill', k: 'bad', c: 1, r: 1, label: '503 fail-closed，不放行' },
      { id: 'c', t: 'dec', c: 0, r: 2, label: '该租户有覆盖值？' },
      { id: 'c1', t: 'pill', k: 'ok', c: 1, r: 2, label: '用覆盖值，与全局无关' },
      { id: 'd', t: 'dec', c: 0, r: 3, label: '全局总开关开启？' },
      { id: 'd1', t: 'pill', k: 'bad', c: 1, r: 3, label: '关闭' },
      { id: 'e', t: 'sys', c: 0, r: 4, label: '按租户 ID 稳定分桶（放量 N%）', sub: '0% = 暂停，100% = 全开' },
      { id: 'f', t: 'pill', k: 'ok', c: 0, r: 5, label: '按开关的作用点生效' }
    ],
    edges: [
      { f: 'a', t: 'b' }, { f: 'b', t: 'b1', l: '否' }, { f: 'b', t: 'c', l: '是' },
      { f: 'c', t: 'c1', l: '是' }, { f: 'c', t: 'd', l: '否' },
      { f: 'd', t: 'd1', l: '否' }, { f: 'd', t: 'e', l: '是' }, { f: 'e', t: 'f' }
    ],
    foot: '顺序固定，不可调换。放量 0% 表示"已发布但不对任何租户开放"，界面上显示为「已暂停」。'
  }
};
