package acl

import (
	"github.com/eaciit/orm/v1"
)

type Access struct {
	orm.ModelBase
	ID             string
	Title          string
	Group1         string
	Group2         string
	Group3         string
	Enable         bool
	SpecialAccess1 string
	SpecialAccess2 string
	SpecialAccess3 string
	SpecialAccess4 string
}

func (a *Access) TableName() string {
	return "Acl_Access"
}

func (a *Access) RecordID() interface{} {
	return a.ID
}
