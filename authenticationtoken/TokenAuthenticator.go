package authenticationtoken

import (
	"aidanwoods.dev/go-paseto"
	"github.com/rs/zerolog/log"
	"sync"
	"time"
)

type TokenAuthenticator struct {
	secretKey              paseto.V4AsymmetricSecretKey
	publicKey              paseto.V4AsymmetricPublicKey
	publicKeyHex           string
	tokenValidityInMinutes int
}

const QUERY_PARAM_USRTOKEN = "usrtoken"

var tokenAuthenticatorMutex = &sync.RWMutex{}
var TokenAuthenticators map[string]*TokenAuthenticator

func init() {
	TokenAuthenticators = map[string]*TokenAuthenticator{}
}

func FetchTokenAuthenticator(secretValue, domain string, validityInMins int) (*TokenAuthenticator, error) {

	var tkAuthenticator *TokenAuthenticator
	tokenAuthenticatorMutex.RLock()
	tkAuthenticator, ok := TokenAuthenticators[domain]
	tokenAuthenticatorMutex.RUnlock()

	var err error = nil
	if !ok {
		log.Debug().Msg("Constructing New Authenticator for domain :" + domain)
		tkAuthenticator, err = NewTokenAuthenticator(secretValue, validityInMins)
		tokenAuthenticatorMutex.Lock()
		TokenAuthenticators[domain] = tkAuthenticator
		tokenAuthenticatorMutex.Unlock()
	}
	return tkAuthenticator, err
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

func (authenticator *TokenAuthenticator) ValidateToken(token string, domain string) (bool, bool, error) {
	parser := paseto.NewParser()
	parser.AddRule(paseto.IssuedBy(domain))
	//parser.AddRule(paseto.Subject(userId))
	_, tokenErr := parser.ParseV4Public(authenticator.publicKey, token, nil)

	isExpired := false
	isInvalid := false
	if tokenErr != nil {
		isExpired = true
		isInvalid = true
	}
	return isExpired, isInvalid, tokenErr
}

//
//func main() {
//	//secretKey, publicKey, publicKeyStr := generateKeys()
//	//log.Debug().Msgf("secretKey : %v", secretKey)
//	//log.Debug().Msgf("secretKeyStr : %v", secretKey.ExportHex())
//	//log.Debug().Msgf("publicKey : %v", publicKey)
//	//log.Debug().Msgf("publicKeyStr : %v", publicKeyStr)
//
//	secretKeyStr := "e329a819b409784a74cf432bea023e051da41bb1e3894a1d1d3810d0d2d752e5b3a913accc6c65af3603db8c52ce33900c5b223b4e695eedb6978692251b8a81"
//	authenticator, _ := NewTokenAuthenticator(secretKeyStr, 2)
//
//	//token := authenticator.GenerateToken("knowme", "sudhakar")
//	//log.Debug().Msgf("token : %v", token)
//
//	tokenStr := "v4.public.eyJleHAiOiIyMDIzLTEwLTAyVDE5OjExOjA2LTA0OjAwIiwiaWF0IjoiMjAyMy0xMC0wMlQxOTowOTowNi0wNDowMCIsImlzcyI6Imtub3dtZSIsIm5iZiI6IjIwMjMtMTAtMDJUMTk6MDk6MDYtMDQ6MDAiLCJzdWIiOiJzdWRoYWthciJ9HVtPiRbAOstZcEFrVsM71AxKDqNjK4RBJQR8O4Eyb83zxSnGB8aqAAEeZ6hOugKOVKhZ-fngzwsalOL3DsAODA"
//	start := time.Now()
//	isExpired, isInvalid, tokenErr := authenticator.ValidateToken(tokenStr, "knowme", "sudhakar1")
//	elapsed := time.Since(start)
//
//	log.Debug().Msgf("ExecutionTime took %s", elapsed)
//	log.Debug().Msgf("isExpired : %v", isExpired)
//	log.Debug().Msgf("isInvalid : %v", isInvalid)
//	log.Debug().Msgf("tokenErr : %v", tokenErr)
//}
