package zkscrypto

// PrivateKey represents a private key.
type PrivateKey struct {
	data []byte
}

// PublicKey represents a public key
type PublicKey struct {
	data []byte
}

// PublicKeyHash represents a public key hash
type PublicKeyHash struct {
	data []byte
}

// Signature represents a multi-signature
type Signature struct {
	data []byte
}
