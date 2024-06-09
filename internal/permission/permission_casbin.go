package permission

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"

	sqladapter "github.com/Blank-Xu/sql-adapter"
	casbin "github.com/casbin/casbin/v2"
	mlog "github.com/mike504110403/goutils/log"
)

// casbinInit : 初始化casbin，決定使用的DB連線與使用的資料表和規則
func casbinInit(db *sql.DB) (*casbin.Enforcer, error) {
	a, err := sqladapter.NewAdapter(db, "mysql", cfg.CasbinTable)
	if err != nil {
		return nil, err
	}

	if e, err := casbin.NewEnforcer(cfg.modelTempPath, a); err != nil {
		return e, err
	} else {
		// 註冊自定義驗證
		e.AddFunction("customMatch", customMatch)
		return e, e.LoadPolicy()
	}
}

// AddPermission : 透過casbin新增角色的權限
func AddPermission(role string, permissions ...string) (bool, error) {
	if result, err := enforcer.AddPermissionForUser(role, permissions...); err != nil {
		return result, err
	} else {
		return result, enforcer.LoadPolicy()
	}
}

// AddPermissions : 透過casbin新增角色的多筆權限
func AddPermissions(role string, permissions ...[]string) (bool, error) {
	if result, err := enforcer.AddPermissionsForUser(role, permissions...); err != nil {
		return result, err
	} else {
		return result, enforcer.LoadPolicy()
	}
}

// DelPermission : 透過casbin刪除角色的權限
func DelPermission(role string, permissions ...string) (bool, error) {
	if result, err := enforcer.DeletePermissionForUser(role, permissions...); err != nil {
		return result, err
	} else {
		return result, enforcer.LoadPolicy()
	}
}

// GetPermissions : 透過casbin取得使用者所有權限
func GetPermissions(user string) ([][]string, error) {
	return enforcer.GetPermissionsForUser(user)
}

// GetRoles : 透過casbin取得使用者所有角色
func GetRoles(user string) ([]string, error) {
	return enforcer.GetRolesForUser(user)
}

// HasPermission : 透過casbin確認使用者具有權限
func HasPermission(user string, permissions ...string) (bool, error) {
	if user != "" && user == cfg.SuperUser {
		return true, nil
	}
	rvals := []interface{}{user}
	rvals = append(rvals, permissions[0], permissions[1])
	return enforcer.Enforce(rvals...)
}

// AddRoleForUser : 設定使用者的角色
func AddRoleForUser(user string, role string) (bool, error) {
	return enforcer.AddRoleForUser(user, role)
}

// AddRolesForUser : 設定使用者的多個角色
func AddRolesForUser(user string, roles []string) (bool, error) {
	return enforcer.AddRolesForUser(user, roles)
}

// DeleteRole : 移除角色及其權限
func DeleteRole(role string) (bool, error) {
	return enforcer.DeleteRole(role)
}

// DeleteRolesForUser : 刪除使用者的所有角色
func DeleteRolesForUser(user string) (bool, error) {
	return enforcer.DeleteRolesForUser(user)
}

// DeleteRoleForUser : 刪除使用者的角色
func DeleteRoleForUser(user string, role string) (bool, error) {
	return enforcer.DeleteRoleForUser(user, role)
}

// UpdateRoleForUser : 更新使用者的角色
func UpdateRoleForUser(user string, roles []string) (bool, error) {
	// 現有角色
	currentRoles, err := GetRoles(user)
	if err != nil {
		mlog.Debug(fmt.Sprintf("casbin角色取得成功: %s", user))
		return false, err
	}
	// 新增角色
	rolesToAdd := difference(roles, currentRoles)
	if rolesToAdd != nil {
		if _, err := AddRolesForUser(user, rolesToAdd); err != nil {
			mlog.Debug(fmt.Sprintf("casbin角色新增成功: %s", user))
			return false, err
		}
	}
	// 移除角色
	rolesToDel := difference(currentRoles, roles)
	if rolesToDel != nil {
		for _, role := range rolesToDel {
			if _, err := DeleteRoleForUser(user, role); err != nil {
				mlog.Debug(fmt.Sprintf("casbin角色刪除失敗: %s, %s", user, role))
				return false, err
			}
		}
	}
	return true, nil
}

func difference(slice1 []string, slice2 []string) []string {
	var diff []string
	m := make(map[string]bool)

	for _, s := range slice2 {
		m[s] = true
	}

	for _, s := range slice1 {
		if !m[s] {
			diff = append(diff, s)
		}
	}

	return diff
}

// GetAllRoles : 取得所有角色
func GetAllRoles() ([]string, error) {
	return enforcer.GetAllRoles()
}

// GetAllRolesWithPermissions : 取得角色們的權限
func GetAllRolesWithPermissions(roles []string) [][]string {
	var result [][]string
	for _, role := range roles {
		permission, err := GetPermissions(role)
		if err != nil {
			log.Fatalf(err.Error())
		}
		result = append(result, permission...)
	}
	return result
}

// GetRolesWithPermissions : 將帶有權限的角色做群組
func GetRolesWithPermissions(rolesWithPermissions [][]string) map[string][]PermissionObj {
	nameTitleMaps := MenuTitleNameMap()

	groupedRolesMap := make(map[string][]PermissionObj)

	for _, rolePermission := range rolesWithPermissions {
		role := rolePermission[0]
		function := rolePermission[1]
		operation := rolePermission[2]
		operations := []string{}
		if operation != "" {
			operations = strings.Split(operation, ",")
		}

		if _, ok := groupedRolesMap[role]; !ok {
			groupedRolesMap[role] = []PermissionObj{}
		}

		var found bool
		for i, permission := range groupedRolesMap[role] {
			if permission.Name == function {
				found = true
				groupedRolesMap[role][i].Operations = append(groupedRolesMap[role][i].Operations, operations...)
				break
			}
		}
		if !found {
			groupedRolesMap[role] = append(groupedRolesMap[role], PermissionObj{Name: function, Operations: operations, Title: nameTitleMaps[function]})
		}
	}

	return groupedRolesMap
}

// customMatch : 多action情況確認權限
func customMatch(args ...interface{}) (interface{}, error) {
	if len(args) != 2 {
		return nil, errors.New("參數數量錯誤")
	}
	reqAct := args[0].(string)
	polAct := args[1].(string)
	// 如果策略中的動作包含請求的動作，则返回 true
	policyActions := strings.Split(polAct, ",")
	for _, action := range policyActions {
		if action == reqAct {
			return true, nil
		}
	}

	return false, nil
}

// OrdeActionStrings : 排序action字串
func OrdeActionStrings(actions []string) string {
	action := Action{}
	for _, a := range actions {
		switch a {
		case "create":
			action.Create = Create
		case "read":
			action.Read = Read
		case "update":
			action.Update = Update
		case "delete":
			action.Delete = Delete
		}
	}

	actionArrary := []string{}
	if action.Create != "" {
		actionArrary = append(actionArrary, action.Create)
	}
	if action.Read != "" {
		actionArrary = append(actionArrary, action.Read)
	}
	if action.Update != "" {
		actionArrary = append(actionArrary, action.Update)
	}
	if action.Delete != "" {
		actionArrary = append(actionArrary, action.Delete)
	}

	newActionString := strings.Join(actionArrary, ",")
	return newActionString
}

// PermissionObjToMap : 多筆Permission物件轉map
func PermissionObjToMap(p []PermissionObj) map[string]string {
	functionsMap := make(map[string]string)
	for _, perm := range p {
		actionStrings := OrdeActionStrings(perm.Operations)
		functionsMap[perm.Name] = actionStrings
	}
	return functionsMap
}

// MenuTitleNameMap : menulist 名稱標題對應
func MenuTitleNameMap() map[string]string {
	menulist := GetMenuList()

	nameTitleMaps := make(map[string]string)

	for _, menu := range menulist {
		currentTitle := menu.Title
		currentName := menu.Name
		if menu.Children != nil {
			for _, chirld := range menu.Children {
				currentTitle = strings.Join([]string{menu.Title, chirld.Title}, "/")
				currentName = strings.Join([]string{menu.Name, chirld.Name}, "/")
				nameTitleMaps[currentName] = currentTitle
			}
		}
		nameTitleMaps[currentName] = currentTitle
	}

	return nameTitleMaps
}

// CheckUserPermissionOperation : 確認使用者指定權限可用操作
func CheckUserPermissionOperation(user string, checkPermission string) ([]string, error) {
	operations := make([]string, 0)
	operationsToCheck := []string{Create, Read, Update, Delete}
	for _, operation := range operationsToCheck {
		hasPermission, err := HasPermission(user, checkPermission, operation)
		if err != nil {
			return operations, err
		}
		if hasPermission {
			operations = append(operations, operation)
		}
	}
	return operations, nil

}
