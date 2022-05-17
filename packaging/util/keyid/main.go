package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
)

func main() {
	var hexData string
	flag.StringVar(&hexData, "h", "", "Hex encoded string")
	flag.Parse()

	if hexData != "" {
		keyId, err := hexToKeyId(hexData)
		if err != nil {
			log.Fatalf(err.Error())
		}

		fmt.Printf("KeyId: %s\n", keyId)
	}
}

func hexToKeyId(hexString string) (string, error) {
	hexBytes, err := hex.DecodeString(hexString)
	if err != nil {
		return "", err
	}

	keyIdBytes := sha256.Sum256(hexBytes)

	return hex.EncodeToString(keyIdBytes[:sha256.Size / 2]), nil
}