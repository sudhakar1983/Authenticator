package authenticationtoken

import (
	"aidanwoods.dev/go-paseto"
	"github.com/rs/zerolog/log"
	"time"
)

type TokenAuthenticator struct {
	secretKey              paseto.V4AsymmetricSecretKey
	publicKey              paseto.V4AsymmetricPublicKey
	publicKeyHex           string
	tokenValidityInMinutes int
}

func NewTokenAuthenticator(secretKeyHex string, validityInMins int) (*TokenAuthenticator, error) {
	secretKey, err := paseto.NewV4AsymmetricSecretKeyFromHex(secretKeyHex)
	publicKey := secretKey.Public()
	if err != nil {
		return nil, err
	}

	return &TokenAuthenticator{
		secretKey:              secretKey,
		publicKey:              publicKey,
		publicKeyHex:           publicKey.ExportHex(),
		tokenValidityInMinutes: validityInMins,
	}, err
}

func generateKeys() (paseto.V4AsymmetricSecretKey, paseto.V4AsymmetricPublicKey, string) {
	secretKey := paseto.NewV4AsymmetricSecretKey() // don't share this!!
	publicKey := secretKey.Public()
	publicKeyStr := publicKey.ExportHex()
	return secretKey, publicKey, publicKeyStr
}

func (authenticator *TokenAuthenticator) GenerateToken(domain string, userId string) string {
	token := paseto.NewToken()
	token.SetIssuer(domain)
	token.SetSubject(userId)

	token.SetIssuedAt(time.Now())
	token.SetNotBefore(time.Now())
	token.SetExpiration(time.Now().Add(time.Duration(authenticator.tokenValidityInMinutes) * time.Minute))
	signed := token.V4Sign(authenticator.secretKey, nil)
	log.Debug().Msgf("signed : %v", signed)
	return signed
}

func (authenticator *TokenAuthenticator) ValidateToken(token string) (bool, bool, error) {
	parser := paseto.NewParser()
	_, tokenErr := parser.ParseV4Public(authenticator.publicKey, token, nil)

	isExpired := false
	isInvalid := false
	if tokenErr != nil {
		isExpired = true
		isInvalid = true
	}
	return isExpired, isInvalid, tokenErr
}

//func main() {
//	//  "golang.org/x/crypto/bcrypt"
//	//  "github.com/golang-jwt/jwt/v5"
//	//secretKey, publicKey, publicKeyStr := generateKeys()
//	//log.Debug().Msgf("secretKey : %v", secretKey)
//	//log.Debug().Msgf("secretKeyStr : %v", secretKey.ExportHex())
//	//log.Debug().Msgf("publicKey : %v", publicKey)
//	//log.Debug().Msgf("publicKeyStr : %v", publicKeyStr)
//
//	secretKeyStr := "e329a819b409784a74cf432bea023e051da41bb1e3894a1d1d3810d0d2d752e5b3a913accc6c65af3603db8c52ce33900c5b223b4e695eedb6978692251b8a81"
//	authenticator, _ := NewTokenAuthenticator(secretKeyStr, 2)
//	token := authenticator.GenerateToken("knowme", "sudhakar")
//	log.Debug().Msgf("token : %v", token)
//
//	start := time.Now()
//	isExpired, isInvalid, tokenErr := authenticator.ValidateToken(token)
//	elapsed := time.Since(start)
//
//	log.Debug().Msgf("ExecutionTime took %s", elapsed)
//	log.Debug().Msgf("isExpired : %v", isExpired)
//	log.Debug().Msgf("isInvalid : %v", isInvalid)
//	log.Debug().Msgf("tokenErr : %v", tokenErr)
//}
