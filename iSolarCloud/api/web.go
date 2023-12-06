package api

import (
	"crypto/aes"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"github.com/MickMake/GoSungrow/iSolarCloud/api/GoStruct"
	"github.com/MickMake/GoSungrow/iSolarCloud/api/GoStruct/output"
	"github.com/MickMake/GoUnify/Only"
	"github.com/MickMake/GoUnify/cmdPath"
	"github.com/andreburgaud/crypt2go/ecb"
	"github.com/andreburgaud/crypt2go/padding"
	"io"
	"math/rand"
	"path/filepath"
	"reflect"
	"strings"
	"time"
	"unsafe"

	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)


type Web struct {
	ServerUrl EndPointUrl
	Body      []byte
	Error     error

	cacheDir     string
	cacheTimeout time.Duration
	retry        int
	client       http.Client
	httpRequest  *http.Request
	httpResponse *http.Response
}


func (w *Web) SetUrl(u string) error {
	w.ServerUrl = SetUrl(u)
	return w.Error
}

func (w *Web) AppendUrl(endpoint string) EndPointUrl {
	return w.ServerUrl.AppendPath(endpoint)
}

func (w *Web) Get(endpoint EndPoint) EndPoint {
	for range Only.Once {
		w.Error = w.ServerUrl.IsValid()
		if w.Error != nil {
			w.Error = errors.New("Sungrow API EndPoint not yet implemented")
			fmt.Println(w.Error)
			break
		}

		isCached := false
		if w.WebCacheCheck(endpoint) {
			isCached = true
		}


		if isCached {
			w.Body, w.Error = w.WebCacheRead(endpoint)
			if w.Error != nil {
				break
			}

		} else {
			w.Body, w.Error = w.getApi(endpoint)
			if w.Error != nil {
				break
			}
		}


		if len(w.Body) == 0 {
			w.Error = errors.New("empty http response")
			break
		}
		endpoint = endpoint.SetResponse(w.Body)
		if endpoint.GetError() != nil {
			w.Error = endpoint.GetError()
			break
		}

		w.Error = endpoint.IsResponseValid()
		if w.Error != nil {
			_ = w.WebCacheRemove(endpoint)
			// fmt.Printf("ERROR: Body is:\n%s\n", w.Body)
			break
		}

		if isCached {
			// Do nothing.
		} else {
			w.Error = w.WebCacheWrite(endpoint, w.Body)
			if w.Error != nil {
				break
			}
		}
	}

	if w.Error != nil {
		endpoint = endpoint.SetError("%s", w.Error)
	}
	return endpoint
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

var src = rand.NewSource(time.Now().UnixNano())

func GenerateRandomWord(n int) string {
	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return *(*string)(unsafe.Pointer(&b))
}

func encryptAES(data, key []byte) ([]byte, error) {

	if len(key) != 16 {
		return nil, fmt.Errorf("key must be 16 characters long")
	}

	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("unable to create cipher: %w", err)
	}

	enc := ecb.NewECBEncrypter(cipher)
	padder := padding.NewPkcs7Padding(cipher.BlockSize())
	data, err = padder.Pad(data)
	if err != nil {
		return nil, fmt.Errorf("unable to pad data: %w", err)
	}
	result := make([]byte, len(data))
	enc.CryptBlocks(result, data)
	hexResult := make([]byte, hex.EncodedLen(len(result)))
	hex.Encode(hexResult, result)

	return hexResult, nil
}

func decryptAES(data, key []byte) ([]byte, error) {
	encrypted := make([]byte, hex.DecodedLen(len(data)))
	if _, err := hex.Decode(encrypted, data); err != nil {
		return nil, fmt.Errorf("failed to decode hex: %w", err)
	}
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("unable to create cipher: %w", err)
	}
	dec := ecb.NewECBDecrypter(cipher)
	plaintext := make([]byte, len(encrypted))
	dec.CryptBlocks(plaintext, encrypted)
	padder := padding.NewPkcs7Padding(cipher.BlockSize())
	plaintext, err = padder.Unpad(plaintext)
	if err != nil {
		return nil, fmt.Errorf("unable to unpad data: %w", err)
	}
	return plaintext, nil
}

func encryptRSA(value []byte, key *rsa.PublicKey) (string, error) {
	encrypted, err := rsa.EncryptPKCS1v15(cryptorand.Reader, key, value)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt: %w", err)
	}
	return base64.URLEncoding.EncodeToString(encrypted), nil
}

func extractUserToken(endpoint EndPoint) (string, error) {
	r := reflect.ValueOf(endpoint.RequestRef())
	token := reflect.Indirect(r).FieldByName("Token").String()
	if token == "" {
		return "", errors.New("empty token")
	}
	i := strings.Index(token, "_")
	if i == -1 || i > len(token)-1 {
		return "", errors.New("malformed token")
	}
	return token[:i], nil
}

const PUB_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCkecphb6vgsBx4LJknKKes-eyj7-RKQ3fikF5B67EObZ3t4moFZyMGuuJPiadYdaxvRqtxyblIlVM7omAasROtKRhtgKwwRxo2a6878qBhTgUVlsqugpI_7ZC9RmO2Rpmr8WzDeAapGANfHN5bVr7G7GYGwIrjvyxMrAVit_oM4wIDAQAB"
const ACCESS_KEY = "9grzgbmxdsp3arfmmgq347xjbza4ysps"

func (w *Web) getApi(endpoint EndPoint) ([]byte, error) {
	parsedKey, err := base64.URLEncoding.DecodeString(PUB_KEY)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pem: %w", err)
	}
	publicKeyInterface, err := x509.ParsePKIXPublicKey(parsedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	publicKey, isRSAPublicKey := publicKeyInterface.(*rsa.PublicKey)
	if !isRSAPublicKey {
		return nil, fmt.Errorf("failed to assert public key: %w", err)
	}

	for range Only.Once {
		request := endpoint.RequestRef()
		w.Error = GoStruct.VerifyOptionsRequired(request)
		if w.Error != nil {
			break
		}

		w.Error = endpoint.IsRequestValid()
		if w.Error != nil {
			break
		}

		u := endpoint.GetUrl()
		w.Error = u.IsValid()
		if w.Error != nil {
			break
		}

		postUrl := w.ServerUrl.AppendPath(u.String()).String()
		var j []byte
		j, w.Error = json.Marshal(request)
		if w.Error != nil {
			break
		}
		randomKey := []byte("web" + GenerateRandomWord(13))
		var data []byte
		data, w.Error = encryptAES(j, randomKey)
		if w.Error != nil {
			break
		}
		var req *http.Request
		req, w.Error = http.NewRequest(http.MethodPost, postUrl, bytes.NewBuffer(data))
		if w.Error != nil {
			break
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-access-key", ACCESS_KEY)
		var secretKey string
		secretKey, w.Error = encryptRSA(randomKey, publicKey)
		if w.Error != nil {
			break
		}
		req.Header.Set("x-random-secret-key", secretKey)

		if token, err := extractUserToken(endpoint); err == nil {
			var limitObj string
			limitObj, w.Error = encryptRSA([]byte(token), publicKey)
			if w.Error != nil {
				break
			}
			req.Header.Set("x-limit-obj", limitObj)
		}

		w.httpResponse, w.Error = w.client.Do(req)

		if w.httpResponse.StatusCode == 401 {
			w.Error = errors.New(w.httpResponse.Status)
			break
		}

		//goland:noinspection GoUnhandledErrorResult,GoDeferInLoop
		defer w.httpResponse.Body.Close()
		if w.Error != nil {
			break
		}

		if w.httpResponse.StatusCode != 200 {
			w.Error = errors.New(fmt.Sprintf("API httpResponse is %s", w.httpResponse.Status))
			break
		}

		w.Body, w.Error = io.ReadAll(w.httpResponse.Body)
		if w.Error != nil {
			break
		}
		w.Body, w.Error = decryptAES(w.Body, randomKey)
		w.Body = bytes.TrimSpace(w.Body)
	}

	return w.Body, w.Error
}

func (w *Web) SetCacheDir(basedir string) error {
	for range Only.Once {
		w.cacheDir = filepath.Join(basedir)

		p := cmdPath.NewPath(basedir)
		if p.DirExists() {
			break
		}

		w.Error = p.MkdirAll()
		if w.Error != nil {
			break
		}

		// _, w.Error = os.Stat(w.cacheDir)
		// if w.Error != nil {
		// 	if os.IsNotExist(w.Error) {
		// 		w.Error = nil
		// 	}
		// 	break
		// }
		//
		// w.Error = os.MkdirAll(w.cacheDir, 0700)
		// if w.Error != nil {
		// 	break
		// }
	}

	return w.Error
}

func (w *Web) GetCacheDir() string {
	return w.cacheDir
}

func (w *Web) SetCacheTimeout(duration time.Duration) {
	w.cacheTimeout = duration
}

func (w *Web) GetCacheTimeout() time.Duration {
	return w.cacheTimeout
}

// WebCacheCheck Retrieves cache data from a local file.
func (w *Web) WebCacheCheck(endpoint EndPoint) bool {
	var ok bool
	for range Only.Once {
		// fn := filepath.Join(w.cacheDir, endpoint.CacheFilename())
		//
		// var f os.FileInfo
		// f, w.Error = os.Stat(fn)
		// if w.Error != nil {
		// 	if os.IsNotExist(w.Error) {
		// 		w.Error = nil
		// 	}
		// 	break
		// }
		//
		// if f.IsDir() {
		// 	w.Error = errors.New("file is a directory")
		// 	break
		// }

		p := cmdPath.NewPath(w.cacheDir, endpoint.CacheFilename())
		if p.DirExists() {
			w.Error = errors.New("file is a directory")
			ok = false
			break
		}
		if !p.FileExists() {
			ok = false
			break
		}

		duration := w.GetCacheTimeout()
		then := p.ModTime()
		then = then.Add(duration)
		now := time.Now()
		if then.Before(now) {
			ok = false
			break
		}

		ok = true
	}

	return ok
}

// WebCacheRead Retrieves cache data from a local file.
func (w *Web) WebCacheRead(endpoint EndPoint) ([]byte, error) {
	fn := filepath.Join(w.cacheDir, endpoint.CacheFilename())
	return output.PlainFileRead(fn)
}

// WebCacheRemove Removes a cache file.
func (w *Web) WebCacheRemove(endpoint EndPoint) error {
	fn := filepath.Join(w.cacheDir, endpoint.CacheFilename())
	return output.FileRemove(fn)
}

// WebCacheWrite Saves cache data to a file path.
func (w *Web) WebCacheWrite(endpoint EndPoint, data []byte) error {
	fn := filepath.Join(w.cacheDir, endpoint.CacheFilename())
	return output.PlainFileWrite(fn, data, output.DefaultFileMode)
}


// PointCacheCheck Retrieves cache data from a local file.
func (w *Web) PointCacheCheck(data DataMap) bool {
	var ok bool
	for range Only.Once {
		p := cmdPath.NewPath(w.cacheDir, "Points.json")
		if p.DirExists() {
			w.Error = errors.New("file is a directory")
			ok = false
			break
		}
		if p.FileExists() {
			ok = true
			break
		}

		duration := w.GetCacheTimeout()
		then := p.ModTime()
		then = then.Add(duration)
		now := time.Now()
		if then.Before(now) {
			break
		}

		ok = true
	}

	return ok
}

// PointCacheRead Retrieves cache data from a local file.
func (w *Web) PointCacheRead(endpoint EndPoint) ([]byte, error) {
	fn := filepath.Join(w.cacheDir, endpoint.CacheFilename())
	return output.PlainFileRead(fn)
}

// PointCacheWrite Saves cache data to a file path.
func (w *Web) PointCacheWrite(endpoint EndPoint, data []byte) error {
	fn := filepath.Join(w.cacheDir, endpoint.CacheFilename())
	return output.PlainFileWrite(fn, data, output.DefaultFileMode)
}
