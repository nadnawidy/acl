package acl

import (
	"github.com/eaciit/orm/v1"
	"time"
)

type Session struct {
	orm.ModelBase
	ID      string    `json:"_id",bson:"_id"`
	UserID  string    // `json:"UserID",bson:"UserID"`
	Created time.Time // `json:"Created",bson:"Created"`
	Expired time.Time // `json:"Expired",bson:"Expired"`
}

func (s *Session) TableName() string {
	return "Acl_Session"
}

func (s *Session) RecordID() interface{} {
	return s.ID
}
