package zkscrypto

import (
	"bytes"
	"testing"
)

func TestPrivateKeyGeneration(t *testing.T) {
	seed := make([]byte, 32)
	expected := []byte{1, 31, 91, 153, 8, 76, 92, 46, 45, 94, 99, 72, 142, 15, 113, 104, 213, 153, 165, 192, 31, 233, 254, 196, 201, 150, 5, 116, 61, 165, 232, 92}
	privateKey, err := NewPrivateKey(seed)
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	if !bytes.Equal(privateKey.data, expected) {
		t.Fatalf("%s,%v,%v must be equal to %v", "Unexpected private key", seed, privateKey.data, expected)
	}
}

func TestPublicKeyGenerationFromPrivateKey(t *testing.T) {
	privateKeyRaw := []byte{1, 31, 91, 153, 8, 76, 92, 46, 45, 94, 99, 72, 142, 15, 113, 104, 213, 153, 165, 192, 31, 233, 254, 196, 201, 150, 5, 116, 61, 165, 232, 92}
	expected := []byte{23, 156, 58, 89, 20, 125, 48, 49, 108, 136, 102, 40, 133, 35, 72, 201, 180, 42, 24, 184, 33, 8, 74, 201, 239, 121, 189, 115, 233, 185, 78, 141}
	pk := PrivateKey{data: privateKeyRaw}

	publicKey, err := pk.PublicKey()
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	if !bytes.Equal(publicKey.data, expected) {
		t.Fatalf("%s,%v must be equal to %v", "Unexpected public key", publicKey.data, expected)
	}
}

func TestHashGenerationFromPublicKey(t *testing.T) {
	publicKeyRaw := []byte{23, 156, 58, 89, 20, 125, 48, 49, 108, 136, 102, 40, 133, 35, 72, 201, 180, 42, 24, 184, 33, 8, 74, 201, 239, 121, 189, 115, 233, 185, 78, 141}
	expected := []byte{199, 113, 39, 22, 185, 239, 107, 210, 23, 83, 196, 233, 29, 236, 195, 81, 177, 17, 192, 109}
	pk := PublicKey{data: publicKeyRaw}

	publicKeyHash, err := pk.Hash()
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	if !bytes.Equal(publicKeyHash.data, expected) {
		t.Fatalf("%s,%v must be equal to %v", "Unexpected public key hash", publicKeyHash.data, expected)
	}
}

func TestSigningMessageUsingPrivateKey(t *testing.T) {
	privateKeyRaw := []byte{1, 31, 91, 153, 8, 76, 92, 46, 45, 94, 99, 72, 142, 15, 113, 104, 213, 153, 165, 192, 31, 233, 254, 196, 201, 150, 5, 116, 61, 165, 232, 92}
	message := []byte("hello")
	expected := []byte{66, 111, 115, 126, 202, 53, 46, 252, 88, 149, 33, 63, 156, 220, 202, 144, 162, 98, 68, 248, 76, 194, 149, 192, 31, 0, 20, 92, 6, 200, 13, 37, 62, 28, 185, 253, 66, 183, 96, 128, 196, 211, 32, 85, 182, 137, 234, 62, 1, 229, 111, 152, 128, 227, 145, 47, 155, 27, 153, 193, 228, 91, 80, 4}
	pk := PrivateKey{data: privateKeyRaw}

	signature, err := pk.Sign(message)
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	if !bytes.Equal(signature.data, expected) {
		t.Fatalf("%s,%v must be equal to %v", "Unexpected signature", signature.data, expected)
	}
}
