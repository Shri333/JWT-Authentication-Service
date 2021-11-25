package helper

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
)

func getPrivateKey(fileName string, password string) (*rsa.PrivateKey, error) {
	privateKeyBytes, err := os.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	privateKeyBlock, _ := pem.Decode(privateKeyBytes)
	// DecryptPEMBlock is deprecated, but the only alternative is using
	// a private key without a password
	privateKeyBytes, err = x509.DecryptPEMBlock(privateKeyBlock, []byte(password))
	if err != nil {
		return nil, err
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func getPublicKey(fileName string) (*rsa.PublicKey, []byte, error) {
	publicKeyBytes, err := os.ReadFile("public.pem")
	if err != nil {
		return nil, nil, err
	}

	publicKeyBlock, _ := pem.Decode(publicKeyBytes)
	genericPublicKey, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	publicKey, ok := genericPublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, nil, err
	}

	return publicKey, publicKeyBytes, nil
}

func Keys(privateKeyFileName string, password string, publicKeyFileName string) (*rsa.PrivateKey, *rsa.PublicKey, []byte, error) {
	privateKey, err := getPrivateKey(privateKeyFileName, password)
	if err != nil {
		return nil, nil, nil, err
	}

	publicKey, publicKeyBytes, err := getPublicKey(publicKeyFileName)
	if err != nil {
		return nil, nil, nil, err
	}

	return privateKey, publicKey, publicKeyBytes, nil
}
