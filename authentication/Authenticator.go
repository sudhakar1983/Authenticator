package authentication

import (
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

//func main() {
//	secret := "iamgod"
//	secretBytes, _ := HashPassword(secret)
//	log.Debug().Msgf("Hashed password :" + string(secretBytes))
//
//	isSame := CheckPasswordHash(secret, string(secretBytes))
//	log.Debug().Msgf("isSame : %s", isSame)
//
//	isSame = CheckPasswordHash(secret, "$2a$10$N/sqEkmMobETrCT7g0m44uap5Cl8E.a0eNPWtPqekYO6BRMgkKGxC")
//	log.Debug().Msgf("isSame : %s", isSame)
//
//	isSame = CheckPasswordHash(secret, "$2a$10$nzRKwdEt/jtA634qtBWU9eDQQUCuTG/k3igzCpFxMeNsmSjplTmaa")
//	log.Debug().Msgf("isSame : %s", isSame)
//}
