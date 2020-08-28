package util

import (
	"encoding/hex"
	"github.com/tickstep/library-go/crypto"
	"github.com/tickstep/library-go/ids"
	"golang.org/x/crypto/bcrypt"
)

func PasswordBCrypto(password string) string {
	cryptPwd, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(cryptPwd)
}

func VerifyPassword(hashPwd string, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashPwd), []byte(password))
	if err != nil{
		return false
	}
	return true
}

// EncryptString 加密
func EncryptString(text string) string {
	if text == "" {
		return ""
	}
	d := []byte(text)
	key := []byte(ids.GetUniqueId("update-service-go", 16))
	r, e := crypto.EncryptAES(d, key)
	if e != nil {
		return text
	}
	return hex.EncodeToString(r)
}

// DecryptString 解密
func DecryptString(text string) string {
	if text == "" {
		return ""
	}
	d, _  := hex.DecodeString(text)
	key := []byte(ids.GetUniqueId("update-service-go", 16))
	r, e := crypto.DecryptAES(d, key)
	if e != nil {
		return text
	}
	return string(r)
}