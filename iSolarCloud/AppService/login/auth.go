package login

import (
	"errors"
	"fmt"
	"time"

	"github.com/MickMake/GoSungrow/iSolarCloud/api"
	"github.com/MickMake/GoSungrow/iSolarCloud/api/GoStruct/output"
	"github.com/MickMake/GoSungrow/iSolarCloud/api/GoStruct/valueTypes"
	"github.com/MickMake/GoUnify/Only"
)

const (
	DateTimeFormat       = "2006-01-02T15:04:05"
	DefaultAuthTokenFile = "AuthToken.json"
	TokenValidHours      = 24
	LastLoginDateFormat  = "2006-01-02 15:04:05"
)

type SunGrowAuth struct {
	AppKey       string
	UserAccount  string
	UserPassword string
	TokenFile    string
	// Token        string
	Force bool

	lastLogin time.Time
	newToken  bool
	// retry        int
	err error
}

func (a *SunGrowAuth) Verify() error {
	var err error
	for range Only.Once {
		if a == nil {
			err = errors.New("no auth details")
			break
		}

		if a.AppKey == "" {
			err = errors.New("API AppKey")
			a.err = err
			break
		}
		if a.UserAccount == "" {
			err = errors.New("empty API Username")
			a.err = err
			break
		}
		if a.UserPassword == "" {
			err = errors.New("empty API Password")
			a.err = err
			break
		}
	}

	return err
}

func (e *EndPoint) Login(auth *SunGrowAuth) error {
	for range Only.Once {
		e.Auth = auth
		e.Request.RequestData = RequestData{
			UserAccount:  valueTypes.SetStringValue(auth.UserAccount),
			UserPassword: valueTypes.SetStringValue(auth.UserPassword),
		}
		e.Request.RequestCommon = api.RequestCommon{
			Appkey: auth.AppKey,
			ApiKeyParam: api.ApiKeyParam{
				Timestamp: time.Now().UnixMilli(),
				Nonce:     api.GenerateRandomWord(32),
			},
			SysCode: "900",
		}

		e.Error = e.Auth.Verify()
		if e.Error != nil {
			break
		}

		e.Error = e.readTokenFile()
		if e.Error != nil {
			break
		}

		if auth.Force {
			e.SetCacheTimeout(time.Second)
			e.SetTokenInvalid() // e.CacheFilename()
			// e.RemoveCache
		}

		if e.IsTokenValid() {
			break
		}

		ep := Assert(e.Call())
		e.Error = ep.GetError()
		if e.Error != nil {
			break
		}
		e.Request = ep.Request
		e.Response = ep.Response
		e.Auth.lastLogin = time.Now()

		if e.IsTokenInvalid() {
			break
		}

		e.Auth.lastLogin = e.Response.ResultData.LoginLastDate.Time
		// e.Auth.lastLogin, _ = time.Parse(LastLoginDateFormat, e.Response.ResultData.LoginLastDate)
		e.Auth.newToken = true

		e.Error = e.saveToken()
		if e.Error != nil {
			break
		}
	}

	return e.Error
}

func (e *EndPoint) SetTokenInvalid() {
	for range Only.Once {
		// e.Auth.Token = ""
		e.Response.ResultData.Token = valueTypes.SetStringValue("")
		e.Auth.newToken = true
		// e.Error = os.Remove(filepath.Join(e.ApiRoot.GetCacheDir(), e.CacheFilename()))
		// if e.Error != nil {
		// 	break
		// }
	}
}

func (e *EndPoint) IsTokenValid() bool {
	for range Only.Once {
		if e.Response.ResponseCommon.IsTokenInvalid() {
			e.SetTokenInvalid()
			break
		}

		if e.Response.ResultData.Token.Match("") {
			e.SetTokenInvalid()
			break
		}

		if e.HoursFromLastLogin() > TokenValidHours {
			e.SetTokenInvalid()
			break
		}

		e.Auth.newToken = false
	}
	return !e.Auth.newToken
}

func (e *EndPoint) IsTokenInvalid() bool {
	return !e.IsTokenValid()
}

func (e *EndPoint) HoursFromLastLogin() float64 {
	return time.Now().Sub(e.Auth.lastLogin).Hours()
}

func (e *EndPoint) HasTokenChanged() bool {
	ok := e.Auth.newToken
	if e.Auth.newToken {
		e.Auth.newToken = false
	}
	return ok
}

func (e *EndPoint) LastLogin() time.Time {
	return e.Auth.lastLogin
}

func (e *EndPoint) Print() {
	fmt.Printf("Email:\t%s\n", e.Email())
	fmt.Printf("Create Date:\t%s\n", e.CreateDate())
	fmt.Printf("Login Last Date:\t%s\n", e.LoginLastDate())
	fmt.Printf("Login Last IP:\t%s\n", e.LoginLastIP())
	fmt.Printf("Login State:\t%s\n", e.LoginState())
	fmt.Printf("User Account:\t%s\n", e.UserAccount())
	fmt.Printf("User Id:\t%s\n", e.UserId())
	fmt.Printf("User Name:\t%s\n", e.UserName())
	fmt.Printf("Is Online:\t%v\n", e.IsOnline())
	fmt.Printf("Token:\t%s\n", e.Token())
	fmt.Printf("Token File:\t%s\n", e.Auth.TokenFile)
}

// Retrieves a token from a local file.
func (e *EndPoint) readTokenFile() error {
	for range Only.Once {
		e.Auth.TokenFile = e.GetFilePath()

		e.Error = output.FileRead(e.Auth.TokenFile, &e.Response)
		if e.Error != nil {
			break
		}

		if e.Token() == "" {
			e.Auth.newToken = true
			break
		}

		// 2022-02-17 14:27:03
		// e.Auth.lastLogin, e.Error = time.Parse(LastLoginDateFormat, e.Response.ResultData.LoginLastDate)
		// if e.Error != nil {
		e.Auth.lastLogin = e.Response.ResultData.LoginLastDate.Time
		if e.Response.ResultData.LoginLastDate.IsZero() {
			e.Auth.newToken = true
			e.Error = nil
			break
		}
	}

	return e.Error
}

// Saves a token to a file path.
func (e *EndPoint) saveToken() error {
	for range Only.Once {
		e.Auth.TokenFile = e.GetFilePath()

		e.Error = output.FileWrite(e.Auth.TokenFile, e.Response, output.DefaultFileMode)
		if e.Error != nil {
			break
		}
	}

	return e.Error
}

// RemoveToken - Removes a token from a file path.
func (e *EndPoint) RemoveToken() error {
	for range Only.Once {
		e.Auth.TokenFile = e.GetFilePath()

		e.Error = output.FileRemove(e.Auth.TokenFile)
		if e.Error != nil {
			break
		}
	}

	return e.Error
}
