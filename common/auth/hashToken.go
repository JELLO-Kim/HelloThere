package auth

import (
	"fmt"
	"github.com/pkg/errors"
)

func hashToken(authorization string) (userName string, err error) {
	if authorization == "" || authorization[:7] != "Bearer " {
		err = errors.New("invalid authorization")
		return
	}
	tokenString := authorization[7:]
	hashedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte("0ne$hOt~P@ssW0rd"), nil
	})
	if err != nil {
		err = errors.New("invalid authorization")
		return
	}

	// validate the essential claims
	if !hashedToken.Valid {
		// handle invalid tokebn
		err = errors.New("token is invalid")
		return
	}
	// map[authorities:[A] client_id:front-ui exp:1.651289877e+09 jti:a0ba5b06-06b6-4ab6-92a8-5cb51f567f36 scope:[read write] user_name:chyun43mast]
	claims, validClaims := hashedToken.Claims.(jwt.MapClaims)
	if !validClaims {
		err = errors.New("access token decode type error")
	}
	name, validName := claims["user_name"]
	if !validName {
		err = errors.New("invalid user name")
	}
	userName = fmt.Sprintf("%s", name)

	return
}
