package authenticationtoken

//package main

import (
	"aidanwoods.dev/go-paseto"
	"fmt"
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

const QUERY_PARAM_USRTOKEN = "token"
const GLOBAL_KEY = "GLOBAL_KEY"
const REFRESH_KEY = "REFRESH"

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

type AuthenticationToken struct {
	Token                   string
	TokenTime               int64
	RefreshToken            string
	ValidityPeriodInMinutes int
	Status                  string
}

// Serial number - to invalidate all tokens if needed.
func (authenticator *TokenAuthenticator) GenerateToken(domain string, subject string, serialNumber string) AuthenticationToken {
	token := paseto.NewToken()
	token.SetIssuer(domain)
	token.SetSubject(subject)
	token.Set(GLOBAL_KEY, serialNumber)

	timeTmp := time.Now()

	token.SetIssuedAt(timeTmp)
	token.SetNotBefore(timeTmp)
	if subject == "admin" {
		token.SetExpiration(timeTmp.Add(time.Duration(authenticator.tokenValidityInMinutes) * time.Hour))
	} else {
		token.SetExpiration(timeTmp.Add(time.Duration(authenticator.tokenValidityInMinutes) * time.Minute))
	}
	//token.SetExpiration(timeTmp.Add(time.Duration(authenticator.tokenValidityInMinutes) * time.Minute))
	signed := token.V4Sign(authenticator.secretKey, nil)
	log.Debug().Msgf("signed : %v", signed)

	authToken := AuthenticationToken{}
	authToken.Token = signed
	authToken.TokenTime = time.Now().Unix()
	authToken.ValidityPeriodInMinutes = authenticator.tokenValidityInMinutes

	return authToken
}

// Could be a security threat
// Include client ip
// TODO : Later - not a priority as Users & applications can use silent authentication to generate new tokens
func (authenticator *TokenAuthenticator) GenerateRefreshToken(domain string, subject string, timeTmp time.Time) AuthenticationToken {
	token := paseto.NewToken()
	token.SetIssuer(domain)
	token.SetSubject(subject)
	token.Set(REFRESH_KEY, REFRESH_KEY)

	token.SetIssuedAt(timeTmp)
	token.SetNotBefore(timeTmp)
	token.SetExpiration(timeTmp.Add(time.Duration(authenticator.tokenValidityInMinutes) * time.Minute))
	signed := token.V4Sign(authenticator.secretKey, nil)
	log.Debug().Msgf("signed : %v", signed)

	authToken := AuthenticationToken{}
	authToken.Token = signed
	authToken.TokenTime = time.Now().Unix()
	authToken.ValidityPeriodInMinutes = authenticator.tokenValidityInMinutes

	return authToken
}

func (authenticator *TokenAuthenticator) ValidateToken(token string, domain string, subject string, serialNumber string) (bool, bool, error) {
	parser := paseto.NewParser()
	parser.AddRule(paseto.IssuedBy(domain))
	parser.AddRule(paseto.Subject(subject))
	parser.AddRule(IsSerialNumValid(serialNumber))
	_, tokenErr := parser.ParseV4Public(authenticator.publicKey, token, nil)

	isExpired := false
	isInvalid := false
	if tokenErr != nil {
		isExpired = true
		isInvalid = true
	}
	return isExpired, isInvalid, tokenErr
}

// SERIAL_NUM validator
func IsSerialNumValid(serialNumber string) paseto.Rule {
	return func(token paseto.Token) error {
		var serialNumberTmp string
		err := token.Get(GLOBAL_KEY, &serialNumberTmp)
		if err != nil {
			return err
		}

		if serialNumber != serialNumberTmp {
			return fmt.Errorf("this token is not valid anymore expected `%s'. `%s' found", serialNumberTmp, serialNumber)
		}
		return nil
	}
}

func main() {

	/*
		//secretKey, publicKey, publicKeyStr := generateKeys()
		//log.Debug().Msgf("secretKey : %v", secretKey)
		//log.Debug().Msgf("secretKeyStr : %v", secretKey.ExportHex())
		//log.Debug().Msgf("publicKey : %v", publicKey)
		//log.Debug().Msgf("publicKeyStr : %v", publicKeyStr)
	*/
	//
	//secretKeyStr := "e329a819b409784a74cf432bea023e051da41bb1e3894a1d1d3810d0d2d752e5b3a913accc6c65af3603db8c52ce33900c5b223b4e695eedb6978692251b8a81"
	//authenticator, _ := NewTokenAuthenticator(secretKeyStr, 2)
	//
	//test_usertoken(authenticator)
	//test_admintoken(authenticator)
}

func test_admintoken(authenticator *TokenAuthenticator) {
	domain := "knowme"
	subject := "admin"
	serialNum := "12345"

	authToken := authenticator.GenerateToken(domain, subject, serialNum)
	isInvalid := test_validateToken(authenticator, domain, subject, serialNum, authToken.Token)
	log.Info().Msgf("test_admintoken: isValid :%v", !isInvalid)
}

func test_usertoken(authenticator *TokenAuthenticator) {
	domain := "knowme"
	subject := "sudhakar112"
	serialNum := "12345"

	authToken := authenticator.GenerateToken(domain, subject, serialNum)
	isInvalid := test_validateToken(authenticator, domain, subject, serialNum, authToken.Token)
	log.Info().Msgf("test_usertoken: isValid :%v", !isInvalid)

	//Wrong subject
	subject = "sudhakar1"
	isInvalid = test_validateToken(authenticator, domain, subject, serialNum, authToken.Token)
	log.Info().Msgf("test_usertoken: Case : When wrong Subject ; Token Result :%v", !isInvalid)

	//Wrong subject
	domain = "knowme"
	subject = "sudhakar112"
	serialNum = "123456"
	isInvalid = test_validateToken(authenticator, domain, subject, serialNum, authToken.Token)
	log.Info().Msgf("test_usertoken: Case : When wrong SerialNum ; Token Result :%v", !isInvalid)

}

func test_generateToken(authenticator *TokenAuthenticator, domain, userid string, serialNum string) AuthenticationToken {
	token := authenticator.GenerateToken(domain, userid, serialNum)
	return token
}

func test_validateToken(authenticator *TokenAuthenticator, domain, subject string, serialNum string, tokenStr string) bool {
	start := time.Now()
	_, isInvalid, tokenErr := authenticator.ValidateToken(tokenStr, domain, subject, serialNum)
	elapsed := time.Since(start)

	if tokenErr != nil {
		log.Error().Msgf("Token err %v", tokenErr)
	}
	log.Debug().Msgf("ExecutionTime took %s", elapsed)
	return isInvalid
}
