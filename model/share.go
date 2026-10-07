/*
 * @Author: LinkLeong link@icewhale.org
 * @Date: 2022-07-26 11:12:12
 * @LastEditors: LinkLeong
 * @LastEditTime: 2022-07-27 14:58:55
 * @FilePath: /CasaOS/model/share.go
 * @Description:
 * @Website: https://www.casaos.io
 * Copyright (c) 2022 by icewhale, All Rights Reserved.
 */
package model

type Shares struct {
	ID        uint   `json:"id"`
	Anonymous bool   `json:"anonymous"`
	Path      string `json:"path"`
	// Username restricts the share to one share account (see SambaUser).
	Username string `json:"username"`
}

// SambaUser is the payload for creating a share account or changing its
// password. It is never returned to a client: the password only travels
// inwards.
type SambaUser struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
