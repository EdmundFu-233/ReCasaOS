/*
 * @Author: LinkLeong link@icewhale.org
 * @Date: 2022-07-26 17:17:57
 * @LastEditors: LinkLeong
 * @LastEditTime: 2022-08-01 17:08:08
 * @FilePath: /CasaOS/service/model/o_connections.go
 * @Description:
 * @Website: https://www.casaos.io
 * Copyright (c) 2022 by icewhale, All Rights Reserved.
 */
package model

// LegacySMBCredentialRowPredicateSQL is the single SQLite storage-class
// contract shared by the expand-only startup gate and the legacy write
// containment DAO. Empty credential identity fields may be NULL or TEXT, but
// an empty envelope is legacy only when it is NULL or a zero-length BLOB.
//
// The credential cutover must replace every consumer of this predicate in the
// same release that writes the first sealed row or migration marker.
const LegacySMBCredentialRowPredicateSQL = `(
	(credential_id IS NULL OR credential_id = '')
	AND (credential_format IS NULL OR credential_format = '')
	AND (
		password_envelope IS NULL
		OR (
			typeof(password_envelope) = 'blob'
			AND length(CAST(password_envelope AS BLOB)) = 0
		)
	)
	AND row_revision = 0
)`

type ConnectionsDBModel struct {
	ID               uint   `gorm:"column:id;primary_key" json:"id"`
	Updated          int64  `gorm:"autoUpdateTime"`
	Created          int64  `gorm:"autoCreateTime"`
	Username         string `json:"username"`
	Password         string `json:"password"`
	CredentialID     string `gorm:"column:credential_id;type:text" json:"-"`
	CredentialFormat string `gorm:"column:credential_format;type:text" json:"-"`
	PasswordEnvelope []byte `gorm:"column:password_envelope;type:blob" json:"-"`
	RowRevision      uint64 `gorm:"column:row_revision;not null;default:0" json:"-"`
	Host             string `json:"host"`
	Port             string `json:"port"`
	Status           string `json:"status"`
	Directories      string `json:"directories"` // string array
	MountPoint       string `json:"mount_point"` //parent directory of mount point
	BootID           string `json:"-"`
	MountIDs         string `json:"-"` // JSON map of share name to Linux mount ID
}

func (p *ConnectionsDBModel) TableName() string {
	return "o_connections"
}
