package acl

// import (
// 	""
// )

type AccessTypeEnum int

const (
	AccessCreate   AccessTypeEnum = 1
	AccessRead                    = 2
	AccessUpdate                  = 4
	AccessDelete                  = 8
	AccessSpecial1                = 16
	AccessSpecial2                = 32
	AccessSpecial3                = 64
	AccessSpecial4                = 128
)

type AccessGrant struct {
	AccessID    string
	AccessValue int
}
