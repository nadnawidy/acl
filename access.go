package acl

import (
	"github.com/eaciit/orm/v1"
)

type Access struct {
	orm.ModelBase
	ID             string
	Title          string
	Group1         int
	Group2         int
	Group3         int
	Enable         bool
	SpecialAccess1 int
	SpecialAccess2 int
	SpecialAccess3 int
	SpecialAccess4 int
}

func (a *Access) TableName() string {
	return "Acl_Access"
}

func (a *Access) RecordID() interface{} {
	return a.ID
}
