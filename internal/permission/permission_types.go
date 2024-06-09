package permission

import (
	"sync"
	"time"
)

type Config struct {
	CasbinTable      string // Casbin資料表的名稱
	SuperUser        string // 超級使用者的名稱或Tag，空字串時無效
	RefreashDuration time.Duration
	modelTempPath    string // 規則存放的暫存路徑，會由流程自動產生，不應從外部帶入
}

type (
	// PermissionExport : 提供外部取用的結構
	PermissionExport struct {
		mux  sync.RWMutex
		Menu []Menu
	}
)

// Menu : 主選單結構
type (
	Menu struct {
		ID          int                   `json:"id"`
		Title       string                `json:"title"`
		Name        string                `json:"name"`
		Enable      bool                  `json:"enable"`
		Permissions map[string]Permission `json:"permissions"`
		Children    []Menu                `json:"children"`
	}

	// Permission : 權限結構
	Permission struct {
		Title  string `json:"title"`
		Enable bool   `json:"enable"`
	}
)

// 角色-權限 對應結構
type (
	// RolePermission : 角色權限對應結構
	RolePermission struct {
		RoleSub       string          `name:"Role"`
		PermissionObj []PermissionObj `name:"Permissions"`
	}
	// PermissionObj : 權限結構
	PermissionObj struct {
		Name       string   `name:"Name"`
		Title      string   `name:"Title"`
		Operations []string `name:"Operations"`
	}
)

// 動作
type Action struct {
	Create string
	Read   string
	Update string
	Delete string
}

// 動作
const (
	Create string = "create"
	Read   string = "read"
	Update string = "update"
	Delete string = "delete"
)
