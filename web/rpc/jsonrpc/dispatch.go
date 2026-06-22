package jsonrpc

import (
	"context"

	"github.com/komari-monitor/komari/pkg/config"
	"github.com/komari-monitor/komari/pkg/rpc"
)

// Dispatch 是所有传输入口的统一分发点：私有站点检查 → 权限校验 → 执行方法。
// ctx 携带可选的取消/超时；meta 为调用者身份元数据（其中 Permission 为权限分组）。
// 始终返回完整的 JsonRpcResponse（包含错误）。
func Dispatch(ctx context.Context, meta *rpc.ContextMeta, req *rpc.JsonRpcRequest) *rpc.JsonRpcResponse {
	if ctx == nil {
		ctx = context.Background()
	}
	if meta == nil {
		meta = &rpc.ContextMeta{Permission: rpc.RoleGuest}
	}
	group := meta.Permission
	if group == "" {
		group = rpc.RoleGuest
	}

	// 私有站点：未登录访客默认拒绝，但保留旧 REST 公开路径迁移到
	// RPC2 后仍必须可访问的 public 方法，否则前端无法读取 /api/me 和
	// /api/public 来显示登录入口。
	if group == rpc.RoleGuest {
		if privateSite, _ := config.GetAs[bool](config.PrivateSiteKey); privateSite {
			if !isPublicRPCAllowedInPrivateSite(req.Method) {
				return rpc.ErrorResponse(req.ID, rpc.PermissionDenied, "Private site enabled, please login first", nil)
			}
		}
	}

	// 命名空间权限校验。
	if !rpc.CheckPermission(group, req.Method) {
		return rpc.ErrorResponse(req.ID, rpc.PermissionDenied, "Permission denied", nil)
	}

	return rpc.CallWithContext(rpc.NewContextWithMeta(ctx, meta), req.ID, req.Method, req.Params)
}

// OnInternalRequest 内部调用 RPC 方法（如服务端代码代发请求），仅携带权限分组。
// group: 调用者权限分组 (guest/client/admin)；method: "namespace:method"；params: 参数。
func OnInternalRequest(ctx context.Context, group string, method string, params interface{}) *rpc.JsonRpcResponse {
	meta := &rpc.ContextMeta{Permission: group}
	req := &rpc.JsonRpcRequest{Version: rpc.RPC_VERSION, Method: method, Params: params}
	return Dispatch(ctx, meta, req)
}

func isPublicRPCAllowedInPrivateSite(method string) bool {
	switch method {
	case "public:getMe",
		"public:getPublicSettings",
		"public:getVersion",
		"public:getClientRecentRecords":
		return true
	default:
		return false
	}
}
