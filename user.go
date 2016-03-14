package acl

import (
	// "github.com/eaciit/dbox"
	"errors"
	"github.com/eaciit/orm/v1"
	"github.com/eaciit/toolkit"
)

type User struct {
	orm.ModelBase
	ID       string        `json:"_id",bson:"_id"`
	LoginID  string        // `json:"LoginID",bson:"LoginID"`
	FullName string        // `json:"FullName",bson:"FullName"`
	Email    string        // `json:"Email",bson:"Email"`
	Password string        // `json:"Password",bson:"Password"`
	Enable   bool          // `json:"Enable",bson:"Enable"`
	Groups   []string      // `json:"Groups",bson:"Groups"`
	Grants   []AccessGrant // `json:"Grants",bson:"Grants"`
}

func (u *User) TableName() string {
	return "Acl_User"
}

func (u *User) RecordID() interface{} {
	return u.ID
}

func (u *User) Grant(tAccessID string, tAccessEnum ...AccessTypeEnum) {
	f, i := getgrantindex(u.Grants, tAccessID)
	if f {
		for _, tAE := range tAccessEnum {
			splittAE := splitgrantvalue(tAE)
			for _, iSplittAE := range splittAE {
				if !matchaccess(iSplittAE, u.Grants[i].AccessValue) {
					u.Grants[i].AccessValue += iSplittAE
				}
			}
		}
	} else {
		sint := 0
		for _, tAE := range tAccessEnum {
			sint += int(tAE)
		}

		if sint == 0 {
			return
		}

		tag := AccessGrant{
			AccessID:    tAccessID,
			AccessValue: sint,
		}

		u.Grants = append(u.Grants, tag)
	}
	return
}

func (u *User) Revoke(tAccessID string, tAccessEnum ...AccessTypeEnum) {
	f, i := getgrantindex(u.Grants, tAccessID)
	if f {
		for _, tAE := range tAccessEnum {
			splittAE := splitgrantvalue(tAE)
			for _, iSplittAE := range splittAE {
				if matchaccess(iSplittAE, u.Grants[i].AccessValue) {
					u.Grants[i].AccessValue -= iSplittAE
				}
			}
		}
	}

	if u.Grants[i].AccessValue == 0 {
		u.Grants = append(u.Grants[:i], u.Grants[i+1:]...)
	}

	return
}

func (u *User) AddToGroup(tGroupID string) error {
	mod := new(Group)
	e := FindByID(mod, tGroupID)
	if e != nil {
		return errors.New("Acl.UserAddToGroup: " + e.Error())
	}

	if !toolkit.HasMember(u.Groups, mod.ID) {
		u.Groups = append(u.Groups, mod.ID)
	}

	for _, tg := range mod.Grants {
		arrgrantval := splitinttogrant(tg.AccessValue)
		u.Grant(tg.AccessID, arrgrantval...)
	}

	return nil
}

func (u *User) RemoveFromGroup(tGroupID string) error {
	mod := new(Group)
	e := FindByID(mod, tGroupID)
	if e != nil {
		return errors.New("Acl.UserAddToGroup: " + e.Error())
	}

	if f, i := toolkit.MemberIndex(u.Groups, mod.ID); f {
		u.Groups = append(u.Groups[:i], u.Groups[i+1:]...)
	}

	for _, tg := range mod.Grants {
		arrgrantval := splitinttogrant(tg.AccessValue)
		u.Revoke(tg.AccessID, arrgrantval...)
	}

	return nil
}
