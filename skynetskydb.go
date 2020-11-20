package skynetskydb

import (
	"bufio"
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
	"os"
	"net/http"
	"encoding/json"
	"io/ioutil"
	"time"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/pbkdf2"
	skynet "github.com/NebulousLabs/go-skynet"

)

const (
	defaultPath string = "/skynet/registry"	
)

////////////////////////////////////////////////////////////////////
// skydb section
// TODO(autisticvegan): REALLY NEED SOME TESTS XD

// returns data and the revision
// TODO(autisticvegan): error handling???
func GetBytesFromRegistry(publicKey string, dataKey string, portal string) ([]byte, int) {
	registryEntry, err := getEntry([]byte(publicKey), []byte(dataKey), portal)
	if err != nil {
		fmt.Println(err)
		return nil, -69
	}
	// download the data
	skynetClient := skynet.NewCustom(portal, skynet.Options{})
	if len(registryEntry.data) == 0 {
		return []byte{}, 0
	}
	// make sure this data is the skylink
	buff, err := skynetClient.Download(registryEntry.data, skynet.DefaultDownloadOptions)
	if err != nil {
		fmt.Println(err)
		return nil, -69
	}
	body, err := ioutil.ReadAll(buff)
	return body, registryEntry.revision
}

// UpdateRegistry will get the registry entry based on the publicKey and dataKey
// If it returns null (the entry doesn't exist), it will make a new one that sets the Key to the dataKey
// if it returns a reg entry, we will increment the revision by 1
// next, set the data of the entry using our data []byte param
// finally, call SetRegistry(privKey, pubKey, current) where current is the RegistryEntry
func UpdateRegistry(privKey []byte, pubKey []byte, dataKey string, skyLink string, portal string) error {
     // Get current document
	current, err := getEntry(pubKey, []byte(dataKey), portal)
    if err != nil {
       current = RegistryEntry{
					datakey: dataKey,
					data: skyLink,
					revision: 0,
                }
	} else {
		current.revision++;
	}
    current.data = skyLink      
    //Set new version
    return setEntry(pubKey, privKey, current, portal);
}

func trimSkylink(sklink string) string {
	return sklink[6:]
}

func SetBytesToRegistry(privateKey string, publicKey string, dataKey string, input []byte, portal string) error {
	skynetClient := skynet.NewCustom(portal, skynet.Options{})
	uploadData := make(skynet.UploadData)
	uploadData[dataKey] = bytes.NewReader(input)

	skylink, err := skynetClient.Upload(uploadData, skynet.DefaultUploadOptions)
	if err != nil {
		fmt.Println(err)
		return err
	}
	// trim skylink
	skylink = trimSkylink(skylink)
	return UpdateRegistry([]byte(privateKey), []byte(publicKey), dataKey, skylink, portal)
}

////////////////////////////////////////////////////////////////////
// registry section
// TODO(autisticvegan): REALLY NEED SOME TESTS XD

// RegistryEntry is a thing
type RegistryEntry struct {
	datakey string
	data string
	revision int
}

type registryResponse struct {
	data []byte
	signature []byte
	revision int
}

//entry for setEntry 
//data
//datakey
//publickey
//revision
//signature

type PublicKeyStruct struct {
	Algorithm string // is ed25519
	Key []byte
}

type EntryToSet struct {
	Data string
	Datakey string
	PublicKey PublicKeyStruct
	Revision int
	Signature []byte
}

func decodeHex(input []byte) []byte {
	dst := make([]byte, hex.DecodedLen(len(input)))
	_, _ = hex.Decode(dst, input)
	return dst
}

func getJSONResponseAndTransformToSignedRegistryEntry(
	resp *http.Response, 
	publicKey ed25519.PublicKey, 
	datakey []byte) RegistryEntry {

	registryResponse := new(registryResponse)
	fmt.Println(resp.Body)
	err := json.NewDecoder(resp.Body).Decode(registryResponse)

	if err != nil {
		return RegistryEntry{
			datakey: string(datakey),
			data: "",
			revision: 0,
		}
	}

	resp.Body.Close()

	/*
	registryEntryToBeHashed := RegistryEntry{
		datakey: string(datakey),
		data: string(registryResponse.data),
		revision: registryResponse.revision,
	}
	// TODO(autisticvegan): Does this actually work? Also need some code hygiene here (looks like doodoo)
	verified := ed25519.Verify(publicKey, 
		hashRegistryEntry(registryEntryToBeHashed), 
		registryResponse.signature)
	if !verified {
		fmt.Println("ed25519 verification was false")
	}
	*/

	returnRegistryEntry := RegistryEntry {
		data: string(decodeHex(registryResponse.data)),
		datakey: string(datakey),
		revision: registryResponse.revision,
	}
	return returnRegistryEntry
}

func getEntry(publicKey ed25519.PublicKey, dataKey []byte, portal string) (RegistryEntry, error) {
	hexDataKey := hex.EncodeToString(hashAll([][]byte{dataKey}))
	hexPublicKey := hex.EncodeToString(publicKey)
    client := &http.Client{Timeout: 30 * time.Second,}
	req, _ := http.NewRequest("GET", portal + defaultPath, nil)
	q := req.URL.Query()
	// should this be "ed25519:" and just the hexdatakey
    q.Add("publickey", "ed25519:" + hexPublicKey)
    q.Add("datakey", hexDataKey)
	// TODO(autisticvegan): What are you going to do about timeouts here? etc (code hygiene needed)
	// req.Header.Add("Accept", "application/json")
	req.URL.RawQuery = q.Encode()
	fmt.Println(req.URL)
	resp, err := client.Do(req)
	if err != nil {
		r := RegistryEntry {
			data: "",
			datakey: hexDataKey,
			revision: 0,
		}
		return r, err
	}
	entry := getJSONResponseAndTransformToSignedRegistryEntry(resp, publicKey, dataKey)
	return entry, nil
}

func setEntry(publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey, entry RegistryEntry, portal string) error {
	sig := ed25519.Sign(privateKey, hashRegistryEntry(entry))

	// data is bytes
	// datakey is hex
	// public key has 2 fields - algorithm: "ed25519" and key: bytes
	// revision is int
	// signature is bytes

	publicKeyStruct := PublicKeyStruct {
		Algorithm: "ed25519",
		Key: publicKey,
	}

	actualEntryToSet := EntryToSet {
		Data: entry.data,
		Datakey: entry.datakey,
		PublicKey: publicKeyStruct,
		Revision: entry.revision,
		Signature: sig,
	}

	marshaledJSON, err := json.Marshal(actualEntryToSet)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("POSTing for setEntry()...")
	client := &http.Client{}
	req, _ := http.NewRequest("POST", portal + defaultPath, bytes.NewBuffer(marshaledJSON))
	req.Header.Set("Content-type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	fmt.Println(resp)
	return nil
}

/////////////////////////////////////////////////
// crypto section
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

// Question: do we have to encode or hash this?
func hashRegistryEntry(registryEntry RegistryEntry) []byte {
	b := [][]byte{
		hashAll([][]byte{[]byte(registryEntry.datakey)}),
		[]byte(registryEntry.data),
		encodeNumber(registryEntry.revision),
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

func WriteNewKeyPairToFile() {
	pub, priv, seed := GenKeyPairAndSeed()
	newline := "\n"
	pubKeyBytes := string([]byte(pub))
	privKeyBytes := string([]byte(priv))
	concatedStr := pubKeyBytes + newline + privKeyBytes + newline + seed
	buf := []byte(concatedStr)
	ioutil.WriteFile("keys.txt", buf, 0644)
}

// ParseKeysFromFile will open a keys.txt and get the keys line by line
func ParseKeysFromFile(path string) (ed25519.PublicKey, ed25519.PrivateKey, string) {
	file, err := os.Open(path)
    if err != nil {
        log.Fatal(err)
    }
    defer file.Close()
	pub := ""
	priv := ""
	seed := ""
	scanner := bufio.NewScanner(file)
	index := 0
    for scanner.Scan() {
		if index == 0 {
			pub = scanner.Text()
		} else if index == 1 {
			priv = scanner.Text()
		} else {
			seed = scanner.Text()
		}
		index++
	}
	return []byte(pub), []byte(priv), seed
}

//to encodeString, use []byte(str)

func GenKeyPairAndSeed() (ed25519.PublicKey, ed25519.PrivateKey, string) {
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
