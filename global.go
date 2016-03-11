package acl

import (
	"errors"
	"github.com/eaciit/dbox"
	_ "github.com/eaciit/dbox/dbc/mongo"
	"github.com/eaciit/orm/v1"
	"github.com/eaciit/toolkit"
)

var _aclconn dbox.IConnection
var _aclctx *orm.DataContext
var _aclctxErr error

type IDTypeEnum int

const (
	IDTypeUser IDTypeEnum = iota
	IDTypeGroup
	IDTypeSession
)

func ctx() *orm.DataContext {
	if _aclctx == nil {
		if _aclconn == nil {
			e := _aclconn.Connect()
			if e != nil {
				_aclctxErr = errors.New("Acl.SetCtx: Test Connect: " + e.Error())
				return nil
			}
		}
		_aclctx = orm.New(_aclconn)
	}
	return _aclctx
}

func SetDb(conn dbox.IConnection) error {
	e := conn.Connect()
	if e != nil {
		_aclctxErr = errors.New("Acl.SetDB: Test Connect: " + e.Error())
		return _aclctxErr
	}

	_aclconn = conn
	return _aclctxErr
}

func Save(o orm.IModel) error {
	e := ctx().Save(o)
	if e != nil {
		return errors.New("Acl.Save: " + e.Error())
	}
	return e
}

func FindByID(o orm.IModel, id interface{}) error {
	e := ctx().GetById(o, id)
	if e != nil {
		return errors.New("Acl.Get: " + e.Error())
	}
	return nil
}

func Delete(o orm.IModel) error {
	e := ctx().Delete(o)
	if e != nil {
		return errors.New("Acl.Delete: " + e.Error())
	}
	return e
}

func HasAccess(ID interface{}, IDType IDTypeEnum, AccessID string, AccessFind AccessTypeEnum) (found bool) {
	found = false

	tGrants := make([]AccessGrant, 0, 0)
	switch IDType {
	case IDTypeUser:
		tUser := new(User)
		err := FindUserByLoginID(tUser, ID)
		if err != nil {
			return
		}
		tGrants = tUser.Grants
	case IDTypeGroup:
		tGroup := new(Group)
		err := FindByID(tGroup, ID)
		if err != nil {
			return
		}
		tGrants = tGroup.Grants
	case IDTypeSession:
		// tSession := new(tSession)
		// err := FindByID(tSession, ID)
		// tGrants = tSession.Grants
	}

	if len(tGrants) == 0 {
		return
	}

	fn, in := getgrantindex(tGrants, AccessID)
	if fn {
		found = matchaccess(int(AccessFind), tGrants[in].AccessValue)
	}

	return
}

func FindUserByLoginID(o orm.IModel, id interface{}) error {
	var filters []*dbox.Filter
	filter := dbox.Eq("loginid", id)
	if filter != nil {
		filters = append(filters, filter)
	}

	c, e := ctx().Find(o, toolkit.M{}.Set("where", filters))
	if e != nil {
		return errors.New("Acl.FindUserByLoginId: " + e.Error())
	}

	defer c.Close()
	e = c.Fetch(o, 1, false)

	return e
}

func FindUserByEmail(o orm.IModel, email string) error {
	var filters []*dbox.Filter
	filter := dbox.Eq("email", email)
	if filter != nil {
		filters = append(filters, filter)
	}

	c, e := ctx().Find(o, toolkit.M{}.Set("where", filters))
	if e != nil {
		return errors.New("Acl.FindUserByEmail: " + e.Error())
	}

	defer c.Close()
	e = c.Fetch(o, 1, false)

	return e
}

func Login(username, password string) {

}

func Logout() {

}

func CreateToken(UserID, TokenPupose, Validity string) {

}

func GetToken(UserID, TokenPurpose string) {

}

func FindUserBySessionID(sesionID string) {

}
