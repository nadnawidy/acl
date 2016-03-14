package acl

import (
	"github.com/eaciit/orm/v1"
)

type Access struct {
	orm.ModelBase
	ID             string `json:"_id",bson:"_id"`
	Title          string // `json:"Title",bson:"Title"`
	Group1         string // `json:"Group1",bson:"Group1"`
	Group2         string // `json:"Group2",bson:"Group2"`
	Group3         string // `json:"Group3",bson:"Group3"`
	Enable         bool   // `json:"Enable",bson:"Enable"`
	SpecialAccess1 string // `json:"SpecialAccess1",bson:"SpecialAccess1"`
	SpecialAccess2 string // `json:"SpecialAccess2",bson:"SpecialAccess2"`
	SpecialAccess3 string // `json:"SpecialAccess3",bson:"SpecialAccess3"`
	SpecialAccess4 string // `json:"SpecialAccess4",bson:"SpecialAccess4"`
}

func (a *Access) TableName() string {
	return "Acl_Access"
}

func (a *Access) RecordID() interface{} {
	return a.ID
}
