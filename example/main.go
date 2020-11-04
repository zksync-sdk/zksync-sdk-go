package main

import (
	"encoding/hex"
	"log"

	"github.com/matter-labs/zksync-sdk/go/zkscrypto"
)

func main() {
	seed := make([]byte, 32)
	message := []byte("hello")

	privateKey, err := zkscrypto.NewPrivateKey(seed)
	if err != nil {
		log.Fatalf("error creating private key: %s", err.Error())
	}
	publicKey, err := privateKey.PublicKey()
	if err != nil {
		log.Fatalf("error creating public key: %s", err.Error())
	}
	publicKeyHash, err := publicKey.Hash()
	if err != nil {
		log.Fatalf("error creating public key hash: %s", err.Error())
	}
	signature, err := privateKey.Sign(message)
	if err != nil {
		log.Fatalf("error signing message: %s", err.Error())
	}
	log.Printf("Seed: %s\n", hex.EncodeToString(seed))
	log.Printf("Private key: %s\n", privateKey.HexString())
	log.Printf("Public key: %s\n", publicKey.HexString())
	log.Printf("Public key hash: %s\n", publicKeyHash.HexString())
	log.Printf("Signature: %s\n", signature.HexString())
}
