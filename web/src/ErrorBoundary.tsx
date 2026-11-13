import { Component, type ErrorInfo, type ReactNode } from 'react'

// 错误边界：任何一个页面渲染抛错，都只影响该页，并给出可读提示。
//
// 起因是一次真实故障：管理台某页签因为接口返回 null（后端把空数组序列化成了 null），
// 组件里对 null 调 .join() 抛错，React 卸载整棵树 —— 用户看到的是"底色铺满、
// 什么都没有"的黑屏，既没有错误信息，也不知道该点哪里。
// 静默失败比报错更难排查。

type Props = { children: ReactNode }
type State = { error: Error | null }

export default class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // 控制台留完整堆栈，便于按 requestId/时间对应服务端日志
    console.error('页面渲染失败', error, info.componentStack)
  }

  render() {
    if (!this.state.error) return this.props.children
    return (
      <div className="login-wrap">
        <div className="login-card" style={{ maxWidth: 640 }}>
          <h1>页面出错了</h1>
          <p className="hint" style={{ marginTop: 0 }}>
            这个页面在渲染时抛出了异常，其他功能不受影响。可以先刷新；若反复出现，
            请把下面的信息反馈给管理员。
          </p>
          <pre className="preview-text" style={{ maxHeight: 200, overflow: 'auto', fontSize: 12 }}>
            {this.state.error.message}
          </pre>
          <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
            <button className="primary" onClick={() => location.reload()}>刷新页面</button>
            <button className="ghost" onClick={() => { this.setState({ error: null }); history.back() }}>
              返回上一页
            </button>
          </div>
        </div>
      </div>
    )
  }
}
