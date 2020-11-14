package skynetcrypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"log"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/pbkdf2"
)

// TODO(autisticvegan): REALLY NEED TO MAKE SOME TESTS XD
func newHash() hash.Hash {
	p, _ := blake2b.New256(nil)
	return p
}

func hashAll(arraysOfBytes [][]byte) []byte {
	hasher := newHash()
	for _, byteArray := range arraysOfBytes {
		r := bytes.NewReader(byteArray)
		if _, err := io.Copy(hasher, r); err != nil {
			log.Fatal(err)
		}
	}
	return hasher.Sum(nil)
}

func hashRegistryEntry(datakey string, data string, revision int) []byte {
	b := [][]byte{
		hashAll([][]byte{[]byte(datakey)}),
		[]byte(data),
		encodeNumber(revision),
	}
	return hashAll(b)
}

func encodeNumber(num int) []byte {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, num)
	if err != nil {
		fmt.Println("binary.Write failed:", err)
	}
	return buf.Bytes()
}

//to encodeString, use []byte(str)

func genKeyPairAndSeed() (ed25519.PublicKey, ed25519.PrivateKey, string) {
	seed := makeSeed(64)
	pub, priv := genKeyPairFromSeed(seed)
	return pub, priv, seed
}

func genKeyPairFromSeed(seed string) (ed25519.PublicKey, ed25519.PrivateKey) {
	actualSeed := pbkdf2.Key([]byte(seed), []byte(""), 1000, 32, sha256.New)
	actualSeedBuffer := bytes.NewReader(actualSeed)
	pub, priv, e := ed25519.GenerateKey(actualSeedBuffer)
	if e != nil {
		fmt.Println("error generating keypair from seed")
	}
	return pub, priv
}

func randomBytes(length int) []byte {
	token := make([]byte, 4)
	_, _ = rand.Read(token)
	return token
}

func makeSeed(length int) string {
	b := randomBytes(length)
	return hex.EncodeToString(b)
}