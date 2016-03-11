package acl

import (
	"fmt"
	"github.com/eaciit/acl"
	"github.com/eaciit/dbox"
	_ "github.com/eaciit/dbox/dbc/mongo"
	"github.com/eaciit/toolkit"
	// "os"
	// "path/filepath"
	"testing"
)

// var err error

// func init() {
// 	conn, err := prepareconnection()

// 	if err != nil {
// 		t.Errorf("Error connecting to database: %s \n", e.Error())
// 	}
// }

func prepareconnection() (conn dbox.IConnection, err error) {
	conn, err = dbox.NewConnection("mongo",
		&dbox.ConnectionInfo{"localhost:27017", "valegrab", "", "", toolkit.M{}.Set("timeout", 3)})
	if err != nil {
		return
	}

	err = conn.Connect()
	return
}

func TestInitialSetDatabase(t *testing.T) {
	conn, err := prepareconnection()

	if err != nil {
		t.Errorf("Error connecting to database: %s \n", err.Error())
	}

	err = acl.SetDb(conn)
	if err != nil {
		t.Errorf("Error set database to acl: %s \n", err.Error())
	}
}

func TestCreateUser(t *testing.T) {
	t.Skip("Skip : Comment this line to do test")
	for i := 0; i < 3; i++ {
		initUser := new(acl.User)

		initUser.ID = toolkit.RandomString(32)
		initUser.LoginID = fmt.Sprintf("ACL.LOGINID.%v", i)
		initUser.FullName = fmt.Sprintf("ACL FULLNAME USER.%v", i)
		initUser.Email = fmt.Sprintf("user.%v.sidik@eaciit.com", i)
		initUser.Password = "12345"

		err := acl.Save(initUser)
		if err != nil {
			t.Errorf("Error set initial user to acl: %s \n", err.Error())
		}
	}
}

func TestCreateAccess(t *testing.T) {
	t.Skip("Skip : Comment this line to do test")
	for i := 0; i < 10; i++ {
		initAccess := new(acl.Access)

		initAccess.ID = fmt.Sprintf("ACLTEST.ACCESS.%v", i)
		initAccess.Title = fmt.Sprintf("ACL.APPS.ACCESS.%v", i)
		initAccess.Group1 = ""
		initAccess.Group2 = ""
		initAccess.Group3 = ""
		initAccess.Enable = true
		initAccess.SpecialAccess1 = ""
		initAccess.SpecialAccess2 = ""
		initAccess.SpecialAccess3 = ""
		initAccess.SpecialAccess4 = ""

		err := acl.Save(initAccess)
		if err != nil {
			t.Errorf("Error set initial Access to acl: %s \n", err.Error())
		}
	}
}

func TestCreateGroup(t *testing.T) {
	t.Skip("Skip : Comment this line to do test")
	for i := 0; i < 4; i++ {
		initGroup := new(acl.Group)

		initGroup.ID = fmt.Sprintf("ACL.GROUP.%v", i)
		initGroup.Title = fmt.Sprintf("ACL.GROUP.TITLE.%v", i)
		initGroup.Enable = true
		initGroup.Grants = nil
		initGroup.Owner = ""

		err := acl.Save(initGroup)
		if err != nil {
			t.Errorf("Error set initial Group to acl: %s \n", err.Error())
		}
	}
}

func TestAddAccesGroup(t *testing.T) {
	t.Skip("Skip : Comment this line to do test")

	tGroup := new(acl.Group)
	err := acl.FindByID(tGroup, "ACL.GROUP.3")

	if err != nil {
		t.Errorf("Error Find By Id in acl: %s \n", err.Error())
	}

	fmt.Printf("Group value from find : %v \n\n", toolkit.JsonString(tGroup))

	tGroup.Grant("ACLTEST.ACCESS.1", acl.AccessCreate+acl.AccessRead+acl.AccessUpdate+acl.AccessDelete)
	tGroup.Grant("ACLTEST.ACCESS.2", acl.AccessCreate, acl.AccessRead)
	tGroup.Grant("ACLTEST.ACCESS.1", acl.AccessRead)

	fmt.Printf("Group after grant : %v \n\n", toolkit.JsonString(tGroup))

	tGroup.Revoke("ACLTEST.ACCESS.1", acl.AccessDelete)
	fmt.Printf("Group after revoke : %v \n\n", toolkit.JsonString(tGroup))

	// err = acl.Save(tGroup)
	// if err != nil {
	// 	t.Errorf("Error save Group to database: %s \n", err.Error())
	// }
}

func TestAddAccesUser(t *testing.T) {
	t.Skip("Skip : Comment this line to do test")

	tUser := new(acl.User)
	err := acl.FindUserByLoginID(tUser, "ACL.LOGINID.1")
	if err != nil {
		t.Errorf("Error Find User By ID ACL: %s \n", err.Error())
	}

	fmt.Printf("User Value : %v \n\n", toolkit.JsonString(tUser))

	tUser.Grant("ACLTEST.ACCESS.2", acl.AccessCreate)
	fmt.Printf("User after grant : %v \n\n", toolkit.JsonString(tUser))

	tUser.AddToGroup("ACL.GROUP.3")
	fmt.Printf("User after add group : %v \n\n", toolkit.JsonString(tUser))

	tUser.Grant("ACLTEST.ACCESS.2", acl.AccessCreate+acl.AccessRead+acl.AccessUpdate+acl.AccessDelete)
	fmt.Printf("User after grant : %v \n\n", toolkit.JsonString(tUser))

	tUser.RemoveFromGroup("ACL.GROUP.3")
	fmt.Printf("User after remove group : %v \n\n", toolkit.JsonString(tUser))
}

func TestFindInAcl(t *testing.T) {
	// t.Skip("Skip : Comment this line to do test")
	tAccess := new(acl.Access)
	tGroup := new(acl.Group)
	tUser := new(acl.User)

	err := acl.FindByID(tAccess, "ACLTEST.ACCESS.1")
	if err != nil {
		t.Errorf("Error Find Access By ID : %s \n", err.Error())
	}
	fmt.Printf("Access value : %v \n\n", toolkit.JsonString(tAccess))

	err = acl.FindByID(tGroup, "ACL.GROUP.1")
	if err != nil {
		t.Errorf("Error Find Group By ID : %s \n", err.Error())
	}
	fmt.Printf("Group value : %v \n\n", toolkit.JsonString(tGroup))

	err = acl.FindUserByLoginID(tUser, "ACL.LOGINID.1")
	if err != nil {
		t.Errorf("Error Find Group By ID : %s \n", err.Error())
	}
	fmt.Printf("User value by login id : %v \n\n", toolkit.JsonString(tUser))

	err = acl.FindUserByEmail(tUser, "user.0.sidik@eaciit.com")
	if err != nil {
		t.Errorf("Error Find Group By ID : %s \n", err.Error())
	}
	fmt.Printf("User value by email : %v \n\n", toolkit.JsonString(tUser))

	foundcond := acl.HasAccess("ACL.LOGINID.1", acl.IDTypeUser, "ACLTEST.ACCESS.8", acl.AccessCreate+acl.AccessRead)
	fmt.Printf("Found has access 01 : %v \n\n", foundcond)

	foundcond = acl.HasAccess("ACL.GROUP.3", acl.IDTypeGroup, "ACLTEST.ACCESS.2", acl.AccessCreate+acl.AccessRead)
	fmt.Printf("Found has access 02 : %v \n\n", foundcond)
}
