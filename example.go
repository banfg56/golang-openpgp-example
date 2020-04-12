package main

import (
  "bytes"
  "io/ioutil"
  "os"

  "crypto"
  _ "crypto/sha256"

  "encoding/json"

  "golang.org/x/crypto/openpgp"
  "golang.org/x/crypto/openpgp/packet"
  "golang.org/x/crypto/openpgp/armor"
)

func _toJson( _data map[string]interface{} )(string){
	res1B, err := json.Marshal(_data)
	if err != nil {
		return ""
	}

	return  string(res1B) 
}

//export enCryptSign
func enCryptSign(encryptionText string, pubKeyringFile string,privKeyringFile string, passPhrase string) (string) {
	sRet :=  map[string]interface{} {"code":500, "msg":"System Error", "data": nil}
	
	// Read in public key
	keyringFileBuffer, _ := os.Open(pubKeyringFile)
	entityList, err := openpgp.ReadKeyRing(keyringFileBuffer)
	if err != nil {
		sRet["msg"] = "读取公钥内容失败," + err.Error()
		return _toJson(sRet)
	}
	defer keyringFileBuffer.Close()

	// Open the private key file
	PriKeyringFileBuffer, err := os.Open(privKeyringFile)
	if err != nil {
		sRet["msg"] =  "打开私钥文件失败" + privKeyringFile
		return _toJson(sRet)
	}

	defer PriKeyringFileBuffer.Close()
	priEntityList, err := openpgp.ReadKeyRing(PriKeyringFileBuffer)
	if err != nil { 
		sRet["msg"] = "读取私钥内容," + err.Error()
		return _toJson(sRet)
	}

	priEntity := priEntityList[0]
	if priEntity.PrivateKey.Encrypted {
		passphraseByte := []byte(passPhrase)
		priEntity.PrivateKey.Decrypt(passphraseByte)
		for _, subkey := range priEntity.Subkeys {
			subkey.PrivateKey.Decrypt(passphraseByte)
		}
	}

	packConfig := packet.Config{
		DefaultHash:            crypto.SHA256,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZIP,
		CompressionConfig: &packet.CompressionConfig{
			Level: 9,
		},
	}

	// encrypt string with armor
	armoEncodeBuf := bytes.NewBuffer(nil)
	armorWriter, err := armor.Encode(armoEncodeBuf, "PGP MESSAGE", nil) // the encoder somehow makes this into ASCII armor
	if err != nil {
		sRet["msg"] = "打开ascii转码失败," + err.Error()
		return _toJson(sRet)
	}
	defer armorWriter.Close()


	// entityList = append(entityList, priEntity)
	// encryptBuf := new(bytes.Buffer)
	encryptorWriter, err := openpgp.Encrypt(armorWriter, entityList, priEntity, nil, &packConfig)
	if err != nil {
		sRet["msg"] = "打开加密失败," + err.Error()
		return _toJson(sRet)
	}
	_, err = encryptorWriter.Write([]byte(encryptionText))
	if err != nil { 
		sRet["msg"] = "读取私钥内容," + err.Error()
		return _toJson(sRet)
	}
	err = encryptorWriter.Close()
	if err != nil { 
		sRet["msg"] = "关闭加密Writer失败," + err.Error()
		return _toJson(sRet)
	}
	armorWriter.Close()
 
	sRet["data"] =  armoEncodeBuf.String() 
	sRet["code"] = 0
	sRet["msg"] = "OK"

	return _toJson(sRet)
}


//export deCrypt
func deCrypt(encStrs string, pubKeyringFile string, privKeyringFile string, passPhrase string) (string) {
	sRet :=  map[string]interface{} {"code":500, "msg":"System Error", "data": nil}

	// armor string decode
	armorBytes := bytes.NewBuffer([]byte(encStrs))
	armorDecoder, err := armor.Decode(armorBytes)
	if err != nil { 
		sRet["msg"] = "PGP 消息解码失败," + err.Error()
		return _toJson(sRet)
	}

	if armorDecoder.Type != "PGP MESSAGE" {
		sRet["msg"] = "无效的 Message格式," + err.Error()
		return _toJson(sRet)
	}

	// Read in public key
	keyringFileBuffer, _ := os.Open(pubKeyringFile)
	entityList, err := openpgp.ReadKeyRing(keyringFileBuffer)
	if err != nil {
		sRet["msg"] = "读取公钥内容失败," + err.Error()
		return _toJson(sRet)
	}
	defer keyringFileBuffer.Close()

	// Open the private key file
	PriKeyringFileBuffer, err := os.Open(privKeyringFile)
	if err != nil {
		sRet["msg"] =  "打开私钥文件失败" + privKeyringFile
		return _toJson(sRet)
	}

	defer PriKeyringFileBuffer.Close()
	priEntityList, err := openpgp.ReadKeyRing(PriKeyringFileBuffer)
	if err != nil { 
		sRet["msg"] = "读取私钥内容," + err.Error()
		return _toJson(sRet)
	}

	priEntity := priEntityList[0]
	if priEntity.PrivateKey.Encrypted {
		passPhraseByte := []byte(passPhrase)
		priEntity.PrivateKey.Decrypt(passPhraseByte)
		for _, subkey := range priEntity.Subkeys {
			subkey.PrivateKey.Decrypt(passPhraseByte)
		}
	}
	entityList = append(entityList, priEntity)

	config := packet.Config{
		DefaultHash:            crypto.SHA256,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZIP,
		CompressionConfig: &packet.CompressionConfig{
			Level: 9,
		},
	}

	messageDetail, err := openpgp.ReadMessage(armorDecoder.Body, entityList, nil, &config)
	if err != nil {
		sRet["msg"] = "读取加密消息失败," + err.Error()
		return _toJson(sRet)
	}
	
	bytes, err := ioutil.ReadAll(messageDetail.UnverifiedBody)
	if err != nil {
		sRet["msg"] = "读取解密内容失败," + err.Error()
		return _toJson(sRet)
	}

	sRet["data"] = string(bytes[:])
	sRet["code"] = 0
	sRet["msg"] = "OK"

	return _toJson(sRet)
}

func main() {
	// runTimePath, err :=  os.Getwd()
	// if err != nil {
	// 	fmt.Println("获取执行决定路径失败，", err)
	// }
	// appDir := filepath.Dir( runTimePath + "/../") + "/"
	
	// // Decode tested OK
	// // resData, err := ioutil.ReadFile( appDir + "data/encryptedMesg.file")
	// // if err != nil {
	// // 	fmt.Println("打开内容失败",err)
	// // }
	// // fmt.Println( deCrypt( string(resData), appDir + "public.gpg", appDir + "secret-key.gpg", "xxxxx") )

	// ennData, err := ioutil.ReadFile( appDir + "data/needEncrypt.file")
	// if err != nil {
	// 	fmt.Println("打开内容失败",err)
	// }
	// fmt.Println( enCryptSign( C.CString(string(ennData)), C.CString(appDir + "public.gpg"), 
	// 			C.CString(appDir + "secret-key.gpg"), C.CString("xxxxxxx")) )
	// fmt.Printf("\n\n\n")
}