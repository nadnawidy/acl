package acl

// import (
// 	""
// )

var listvalue = []int{1, 2, 4, 8, 16, 32, 64, 128}
var listgrantvalue = []AccessTypeEnum{1, 2, 4, 8, 16, 32, 64, 128}

func splitgrantvalue(in AccessTypeEnum) []int {
	ain := make([]int, 0, 0)
	for _, i := range listvalue {
		if matchaccess(i, int(in)) {
			ain = append(ain, i)
		}
	}
	return ain
}

func splitinttogrant(in int) []AccessTypeEnum {
	ain := make([]AccessTypeEnum, 0, 0)
	for _, i := range listgrantvalue {
		if matchaccess(int(i), in) {
			ain = append(ain, i)
		}
	}
	return ain
}

func matchaccess(searchAccess int, sourceAccess int) bool {
	if searchAccess == (searchAccess & sourceAccess) {
		return true
	}
	return false
}

func getgrantindex(ag []AccessGrant, AccessID string) (found bool, in int) {
	found = false
	for i, v := range ag {
		if v.AccessID == AccessID {
			in = i
			found = true
			break
		}
	}

	return
}

func getlastpassword(UserId string) (passwd string) {
	passwd = ""

	tUser := new(User)
	err := FindByID(tUser, UserId)
	if err != nil {
		return
	}

	passwd = tUser.Password

	return
}
