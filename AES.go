package Mytools

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

/*
   AES  CBC 加密
   key:加密key
   plaintext：加密明文
   ciphertext:解密返回字节字符串[ 整型以十六进制方式显示]

*/
func AESCBCEncrypt(key, plaintext string) (ciphertext string) {
	plainbyte := []byte(plaintext)
	keybyte := []byte(key)
	if len(plainbyte)%aes.BlockSize != 0 {
		panic("plaintext is not a multiple of the block size")
	}
	block, err := aes.NewCipher(keybyte)
	if err != nil {
		panic(err)
	}

	cipherbyte := make([]byte, aes.BlockSize+len(plainbyte))
	iv := cipherbyte[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherbyte[aes.BlockSize:], plainbyte)

	ciphertext = fmt.Sprintf("%x\n", cipherbyte)
	return
}

/*
   AES  CBC 解码
   key:解密key
   ciphertext:加密返回的串
   plaintext：解密后的字符串
*/
func AESCBCDecrypter(key, ciphertext string) (plaintext string) {
	cipherbyte, _ := hex.DecodeString(ciphertext)
	keybyte := []byte(key)
	block, err := aes.NewCipher(keybyte)
	if err != nil {
		panic(err)
	}
	if len(cipherbyte) < aes.BlockSize {
		panic("ciphertext too short")
	}

	iv := cipherbyte[:aes.BlockSize]
	cipherbyte = cipherbyte[aes.BlockSize:]
	if len(cipherbyte)%aes.BlockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(cipherbyte, cipherbyte)

	//fmt.Printf("%s\n", ciphertext)
	plaintext = string(cipherbyte[:])
	return
}

/*
   AES  GCM 加密
   key:加密key
   plaintext：加密明文
   ciphertext:解密返回字节字符串[ 整型以十六进制方式显示]

*/
func AESGCMEncrypt(key, plaintext string) (ciphertext, noncetext string) {
	plainbyte := []byte(plaintext)
	keybyte := []byte(key)
	block, err := aes.NewCipher(keybyte)
	if err != nil {
		panic(err.Error())
	}

	// 由于存在重复的风险，请勿使用给定密钥使用超过2^32个随机值。
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	cipherbyte := aesgcm.Seal(nil, nonce, plainbyte, nil)
	ciphertext = fmt.Sprintf("%x\n", cipherbyte)
	noncetext = fmt.Sprintf("%x\n", nonce)
	return
}

/*
   AES  CBC 解码
   key:解密key
   ciphertext:加密返回的串
   plaintext：解密后的字符串
*/
func AESGCMDecrypter(key, ciphertext, noncetext string) (plaintext string) {
	cipherbyte, _ := hex.DecodeString(ciphertext)
	nonce, _ := hex.DecodeString(noncetext)
	keybyte := []byte(key)
	block, err := aes.NewCipher(keybyte)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plainbyte, err := aesgcm.Open(nil, nonce, cipherbyte, nil)
	if err != nil {
		panic(err.Error())
	}

	//fmt.Printf("%s\n", ciphertext)
	plaintext = string(plainbyte[:])
	return
}

func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

//AesEncrypt 加密函数
func AesEncrypt(plaintext []byte, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	plaintext = PKCS7Padding(plaintext, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, iv)
	crypted := make([]byte, len(plaintext))
	blockMode.CryptBlocks(crypted, plaintext)
	return crypted, nil
}

// AesDecrypt 解密函数
func AesDecrypt(ciphertext []byte, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, iv[:blockSize])
	origData := make([]byte, len(ciphertext))
	blockMode.CryptBlocks(origData, ciphertext)
	origData = PKCS7UnPadding(origData)
	return origData, nil
}

func JiaMi(str string) string {
	key, _ := hex.DecodeString("b062c935d3ac65d5b0615cb37d8939fa")
	plaintext := []byte(str)
	c := make([]byte, aes.BlockSize+len(plaintext))
	iv := c[:aes.BlockSize]
	ciphertext, err := AesEncrypt(plaintext, key, iv)
	if err != nil {
		panic(err)
	}

	return base64.StdEncoding.EncodeToString(ciphertext)

}

func JieMi(str string) string {
	key, _ := hex.DecodeString("b062c935d3ac65d5b0615cb37d8939fa")
	plaintext := []byte(str)
	c := make([]byte, aes.BlockSize+len(plaintext))
	iv := c[:aes.BlockSize]
	re, _ := base64.StdEncoding.DecodeString(str)
	plaintext, _ = AesDecrypt(re, key, iv)

	return string(plaintext)
}
