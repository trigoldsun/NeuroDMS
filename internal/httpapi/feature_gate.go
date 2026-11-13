package httpapi

import (
	"context"
	"fmt"

	"docvault/internal/feature"
)

// 开关拦截的统一入口。
//
// 这里有两个此前踩过的坑，集中在这一个文件里避免各入口再犯：
//
//  1. **读完失败不能说"那就开着吧"。** 原先几处写的是
//     `if ok, err := Enabled(...); err == nil && !ok { 拒绝 }`，
//     意思是读库出错就跳过拦截。而开关被用来的场景恰恰是合规关闭
//     （对外分享、转码、自定义域名），数据库抖动一下就会让"已关闭的能力"
//     对所有人自动打开——这是最不该 fail-open 的地方。
//
//  2. **拒绝理由要说清是谁关的。** 只说"未开启，请联系运营"时，
//     运营打开控制台看到"总开关已开启"，双方互相等，最后只能来问开发。
//     所以这里按来源（override / rollout / default）给出不同文案。

// featureState 读取开关有效值；调用方必须处理 err（按 fail-closed 处理）。
func (a *API) featureState(ctx context.Context, tenantID, code string) (feature.EffectiveFlag, error) {
	if a.Features == nil {
		// 未装配开关服务时视为"功能不可用"，而不是"全开"：
		// 装配错误不应该变成一次静默的能力放开。
		return feature.EffectiveFlag{}, fmt.Errorf("开关服务未启用")
	}
	return a.Features.Evaluate(ctx, tenantID, code)
}

// featureDenyMessage 把取值来源翻译成用户能行动的一句话。
func featureDenyMessage(f feature.EffectiveFlag, ability string) string {
	switch f.Source {
	case "override":
		return fmt.Sprintf("平台已单独关闭本租户的%s能力，请联系平台运营恢复", ability)
	case "rollout":
		if f.RolloutPercent <= 0 {
			return fmt.Sprintf("平台已暂停%s能力的放量（当前放量 0%%），请联系平台运营开放", ability)
		}
		return fmt.Sprintf("本租户当前不在%s能力的放量范围内（放量 %d%%），请联系平台运营", ability, f.RolloutPercent)
	default:
		return fmt.Sprintf("当前未开启%s能力，请联系平台运营", ability)
	}
}
