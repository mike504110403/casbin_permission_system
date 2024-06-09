package permission

import (
	//"crypto-backstage-api/internal/database"
	"embed"
	"time"

	tempfile "github.com/mike504110403/goutils/tempFile"

	casbin "github.com/casbin/casbin/v2"
	_ "github.com/go-sql-driver/mysql"
	mlog "github.com/mike504110403/goutils/log"
)

//go:embed rbac_model.conf
var modelFS embed.FS

//go:embed menu.json
var menuFS embed.FS

var cfg Config
var userMenuListMap = map[string][]Menu{}
var nextRefreshTime = time.Now()

var (
	enforcer *casbin.Enforcer

	permissionExport = &PermissionExport{}
)

// Init : 初始化，取得menu.json與rbac config
func Init(initCfg Config) (err error) {
	cfg = initCfg
	nextRefreshTime = time.Now().Add(-1 * cfg.RefreashDuration)

	// 讀取rbac規則，並建立臨時資料夾提供套件臨時路徑讀取
	if modelFile, err := modelFS.ReadFile("rbac_model.conf"); err != nil {
		return err
	} else {
		if fileInfo, err := tempfile.TempFile(modelFile); err != nil {
			return err
		} else {
			cfg.modelTempPath = fileInfo.Path
			defer func() {
				if err := fileInfo.Delete(); err != nil {
					mlog.Fatal(err.Error())
				}
			}()
		}
	}

	// 讀取menu.json
	if menuFile, err := menuFS.ReadFile("menu.json"); err != nil {
		return err
	} else {
		if menuList, err := loadMenu(menuFile); err != nil {
			return err
		} else {
			permissionExport.Menu = menuList
		}
	}

	// if db, err := database.CRYPTO.DB(); err != nil {
	// 	return err
	// } else {
	// 	// 初始化casbin套件
	// 	if e, err := casbinInit(db); err != nil {
	// 		return err
	// 	} else {
	// 		enforcer = e
	// 	}
	// }

	return nil
}

// ReInit : 重新載入
func ReInit() error {
	if menuFile, err := menuFS.ReadFile("menu.json"); err != nil {
		return err
	} else {
		if menuList, err := loadMenu(menuFile); err != nil {
			return err
		} else {
			permissionExport.Menu = menuList
		}
	}

	return nil
}

// CheckPermission : 檢查權限，傳入字串陣列不為2則直接回傳不存在
func CheckPermission(userID string, p ...string) (bool, bool) {
	pass, exist := false, false
	if len(p) != 2 {
		return pass, exist
	}
	menuTag, permission := p[0], p[1]
	pass, err := HasPermission(userID, menuTag, permission)
	if err != nil {
		mlog.Fatal(err.Error())
	}
	exist = true
	return pass, exist
}

// GetMenuList : 取得menu
func GetMenuList() []Menu {
	permissionExport.mux.RLock()
	defer permissionExport.mux.RUnlock()
	return permissionExport.Menu
}

// GetUserMenuList : 依照使用者拿到的使用者權限去篩選選單,並且設置一個刷新時間(大約1分)，當這個時間到了，才會重新載入選單資料
func GetUserMenuList(userID string) []Menu {
	userMenuList, isExist := userMenuListMap[userID]
	// 如果有找到並且刷新時間還沒有到，就直接返回
	if isExist && nextRefreshTime.After(time.Now()) {
		return userMenuList
	}
	userMenuListMap[userID] = menuListFilter(GetMenuList(), "", userID)
	nextRefreshTime = time.Now().Add(cfg.RefreashDuration)

	return userMenuListMap[userID]
}

// isSuper : 判斷是否為超級使用者，如果未設定則無超級使用者
func isSuper(userID string) bool {
	if cfg.SuperUser != "" && userID == cfg.SuperUser {
		return true
	}
	return false
}
