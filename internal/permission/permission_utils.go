package permission

import (
	"encoding/json"

	mlog "github.com/mike504110403/goutils/log"
)

// loadMenu : 從menu.json取得選單與權限資料
func loadMenu(data []byte) (menuList []Menu, err error) {
	if err := json.Unmarshal(data, &menuList); err != nil {
		return menuList, err
	}
	return menuList, nil
}

// menuListFilter : 依照使用者拿到的使用者權限去篩選選單
func menuListFilter(menuList []Menu, parentMenu string, userID string) []Menu {
	userMenuList := []Menu{}
	for _, menu := range menuList {
		if len(menu.Children) > 0 {
			// 如果有子項目，表示是一層選單，沒有權限功能，直接跳過
			children := menuListFilter(menu.Children, menu.Name+"/", userID)
			if len(children) > 0 {
				// 如果有具權限的子項目才裝載選單項目
				menu.Children = children
				userMenuList = append(userMenuList, menu)
			}
		} else {
			if isSuper(userID) {
				menu.Children = make([]Menu, 0)
				userMenuList = append(userMenuList, menu)
			} else {
				permissionStr := parentMenu + menu.Name
				haspermission, err := HasPermission(userID, permissionStr, "read")
				if err != nil {
					mlog.Fatal(err.Error())
				}
				if haspermission {
					menu.Children = make([]Menu, 0)
					userMenuList = append(userMenuList, menu)
				}
			}
		}
	}
	return userMenuList
}
