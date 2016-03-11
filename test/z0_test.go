package acl

import (
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
	initUser := new(acl.User)

	initUser.LoginID = "alip"
	initUser.FullName = "alip sidik"
	initUser.Email = "aa.sidik@eaciit.com"
	initUser.Password = "12345"

	err := acl.Save(initUser)
	if err != nil {
		t.Errorf("Error set initial user to acl: %s \n", err.Error())
	}
}
