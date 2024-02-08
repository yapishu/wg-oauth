package structs

import (
	"time"
)

type UserCookie struct {
	Username string    `json:"Username"`
	IsAdmin  bool      `json:"isAdmin"`
	Email    string    `json:"email"`
	Expires  time.Time `json:expires`
}
