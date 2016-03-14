package acl

import (
	"errors"
	"fmt"
	"github.com/eaciit/dbox"
	_ "github.com/eaciit/dbox/dbc/mongo"
	"github.com/eaciit/orm/v1"
	"github.com/eaciit/toolkit"
	"time"
)

var _aclconn dbox.IConnection
var _aclctx *orm.DataContext
var _aclctxErr error
var _expiredduration time.Duration

type IDTypeEnum int

const (
	IDTypeUser IDTypeEnum = iota
	IDTypeGroup
	IDTypeSession
)

func init() {
	_expiredduration = time.Minute * 30
}

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

func SetExpiredDuration(td time.Duration) {
	_expiredduration = td
}

func Save(o orm.IModel) error {
	e := ctx().Save(o)
	if e != nil {
		return errors.New("Acl.Save: " + e.Error())
	}
	return e
}

func Find(o orm.IModel, filter *dbox.Filter, config toolkit.M) (dbox.ICursor, error) {
	var filters []*dbox.Filter
	if filter != nil {
		filters = append(filters, filter)
	}

	dconf := toolkit.M{}.Set("where", filters)
	if config != nil {
		if config.Has("take") {
			dconf.Set("limit", config["take"])
		}
		if config.Has("skip") {
			dconf.Set("skip", config["skip"])
		}
	}

	c, e := ctx().Find(o, dconf)
	if e != nil {
		return nil, errors.New("Acl.Find: " + e.Error())
	}
	return c, nil
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
		tSession := new(Session)
		err := FindByID(tSession, ID)
		if tSession.Expired.Before(time.Now().UTC()) {
			return
		}

		tUser := new(User)
		err = FindByID(tUser, tSession.UserID)
		if err != nil {
			return
		}

		tGrants = tUser.Grants
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
	filter := dbox.Eq("loginid", id)

	c, e := Find(o, filter, nil)
	if e != nil {
		return errors.New("Acl.FindUserByLoginId: " + e.Error())
	}

	defer c.Close()
	e = c.Fetch(o, 1, false)

	return e
}

func FindUserByEmail(o orm.IModel, email string) error {
	filter := dbox.Eq("email", email)
	c, e := Find(o, filter, nil)

	if e != nil {
		return errors.New("Acl.FindUserByEmail: " + e.Error())
	}

	defer c.Close()
	e = c.Fetch(o, 1, false)

	return e
}

func Login(username, password string) (sessionid string, err error) {

	tUser := new(User)
	err = FindUserByLoginID(tUser, username)
	if err != nil {
		return
	}

	if password != tUser.Password {
		err = errors.New("Username and password is not correct")
		return
	}

	tSession := new(Session)
	tSession.ID = toolkit.RandomString(32)
	tSession.UserID = tUser.ID
	tSession.Created = time.Now().UTC()
	tSession.Expired = time.Now().UTC().Add(_expiredduration)

	err = Save(tSession)
	if err == nil {
		sessionid = tSession.ID
	}
	return
}

func Logout(sessionid string) (err error) {
	tSession := new(Session)
	err = FindByID(tSession, sessionid)
	if err != nil {
		err = errors.New(fmt.Sprintf("Get session, Found error : %s", err.Error()))
		return
	}

	if tSession.ID == "" {
		err = errors.New("Session id not found")
		return
	}

	if time.Now().UTC().After(tSession.Expired) {
		err = errors.New("Session id is expired")
		return
	}

	tSession.Expired = time.Now().UTC()
	err = Save(tSession)
	if err != nil {
		err = errors.New(fmt.Sprintf("Save session, Found error : %s", err.Error()))
	}

	return
}

func CreateToken(UserID, TokenPupose string, Validity time.Duration) (err error) {
	tToken := new(Token)
	tToken.ID = toolkit.RandomString(32)
	tToken.UserID = UserID
	tToken.Created = time.Now().UTC()
	tToken.Expired = time.Now().UTC().Add(Validity)
	tToken.Purpose = TokenPupose

	err = Save(tToken)

	return
}

func GetToken(UserID, TokenPurpose string) (tokenid string, err error) {
	tToken := new(Token)

	var filters []*dbox.Filter
	filter := dbox.And(dbox.Eq("userid", UserID), dbox.Eq("purpose", TokenPurpose))
	if filter != nil {
		filters = append(filters, filter)
	}

	c, err := ctx().Find(tToken, toolkit.M{}.Set("where", filters))
	if err != nil {
		err = errors.New("Acl.GetToken: " + err.Error())
		return
	}

	defer c.Close()
	err = c.Fetch(tToken, 1, false)

	if err == nil {
		if time.Now().UTC().After(tToken.Expired) {
			err = errors.New("Token has been expired")
			tToken = new(Token)
			return
		}

		if !tToken.Claimed.IsZero() {
			err = errors.New("Token has been claimed")
			tToken = new(Token)
			return
		}

		tokenid = tToken.ID
	}

	return
}

func FindUserBySessionID(sessionid string) (tUser orm.IModel, err error) {
	tSession := new(Session)
	err = FindByID(tSession, sessionid)
	if err != nil {
		return
	}

	if tSession.Expired.Before(time.Now().UTC()) {
		err = errors.New(fmt.Sprintf("Session has been expired"))
		return
	}

	tSession.Expired = time.Now().UTC().Add(_expiredduration)
	err = Save(tSession)
	if err != nil {
		err = errors.New(fmt.Sprintf("Update session error found : ", err.Error()))
	}

	tUser = new(User)
	err = FindByID(tUser, sessionid)
	if err != nil {
		err = errors.New(fmt.Sprintf("Find user by id found : ", err.Error()))
	}
	// userid = tSession.UserID

	return
}
