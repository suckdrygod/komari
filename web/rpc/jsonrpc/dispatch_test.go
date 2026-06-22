package jsonrpc

import (
	"context"
	"strings"
	"testing"

	"github.com/komari-monitor/komari/pkg/config"
	"github.com/komari-monitor/komari/pkg/rpc"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestDispatchPrivateSiteAllowsLoginBootstrapMethods(t *testing.T) {
	setupDispatchConfigDB(t, true)

	for _, method := range []string{"public:getMe", "public:getVersion"} {
		t.Run(method, func(t *testing.T) {
			resp := Dispatch(context.Background(), &rpc.ContextMeta{Permission: rpc.RoleGuest}, rpc.NewRequest("1", method, nil))
			require.NotNil(t, resp)
			require.Nil(t, resp.Error)
		})
	}
}

func TestDispatchPrivateSiteBlocksOtherGuestPublicMethods(t *testing.T) {
	setupDispatchConfigDB(t, true)

	resp := Dispatch(context.Background(), &rpc.ContextMeta{Permission: rpc.RoleGuest}, rpc.NewRequest("1", "public:getNodesInformation", nil))
	require.NotNil(t, resp)
	require.NotNil(t, resp.Error)
	require.Equal(t, rpc.PermissionDenied, resp.Error.Code)
}

func TestPublicRPCAllowedInPrivateSiteWhitelist(t *testing.T) {
	allowed := []string{
		"public:getMe",
		"public:getPublicSettings",
		"public:getVersion",
		"public:getClientRecentRecords",
	}
	for _, method := range allowed {
		require.True(t, isPublicRPCAllowedInPrivateSite(method), method)
	}

	blocked := []string{
		"public:getNodesInformation",
		"public:getRecordsByUUID",
		"public:getPingRecords",
		"public:getPublicPingTasks",
		"admin:getUsers",
	}
	for _, method := range blocked {
		require.False(t, isPublicRPCAllowedInPrivateSite(method), method)
	}
}

func setupDispatchConfigDB(t *testing.T, privateSite bool) {
	t.Helper()

	name := strings.NewReplacer("/", "_", " ", "_").Replace(t.Name())
	db, err := gorm.Open(sqlite.Open("file:"+name+"?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() {
		_ = sqlDB.Close()
	})

	config.SetDb(db)
	require.NoError(t, config.Set(config.PrivateSiteKey, privateSite))
}
