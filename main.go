package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/davecgh/go-spew/spew"

	"github.com/hashicorp/vault/shamir"
	log "github.com/sirupsen/logrus"
)

const (
	version = "0.3"
)

type StorageData struct {
	Key      string
	Value    string
	binValue []byte
}

func getStorageValue(target string) (data *StorageData, err error) {
	ciphertext, err := ioutil.ReadFile(target)
	if err != nil {
		return nil, fmt.Errorf("ReadFile: %s", err)
	}

	data = &StorageData{}
	if err := json.Unmarshal(ciphertext, &data); err != nil {
		return nil, fmt.Errorf("Failed to deserialize storage data: %s", err)
	}
	data.binValue, err = base64.StdEncoding.DecodeString(fmt.Sprintf("%s", data.Value))
	if err != nil {
		return nil, fmt.Errorf("base64 decoding: %s", err)
	}
	log.Debugf("StorageData: %s", spew.Sdump(data))
	return data, nil
}
func main_() int {
	log.SetOutput(os.Stdout)
	log.SetFormatter(&log.TextFormatter{})
	log.Infof("Vault-decrypt starting version %s", version)

	keyRingPath := flag.String("key-ring", "tmp/data/core/keyring", "Path to a file with the keyring")
	encryptedKeyPath := flag.String("encrypted-file", "", "Path to the file to decrypt")
	unsealKeysPath := flag.String("unseal-keys", "", "Path to a file with the unseal keys, one per line")
	debug := flag.Bool("debug", false, "Enable debug output (optional)")
	flag.Parse()

	if len(os.Args) < 6 {
		flag.PrintDefaults()
		os.Exit(1)
	}
	log.SetLevel(log.InfoLevel)
	if *debug {
		log.SetLevel(log.DebugLevel)
	}

	//Read unseal keys from file
	unsealKeysText, err := ioutil.ReadFile(*unsealKeysPath)
	if err != nil {
		log.Fatalf("ReadFile: %s", err)
		return 1
	}
	unsealKeys := strings.Split(string(unsealKeysText), "\n")
	if unsealKeys[len(unsealKeys)-1] == "" {
		unsealKeys = unsealKeys[:len(unsealKeys)-1]
	}
	log.Debugf("Unseal keys=%s", spew.Sdump(unsealKeys))
	//Decode base64 shamir keys and combine them
	var unsealKeysBins [][]byte
	for _, v := range unsealKeys {
		tmpBin, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			log.Fatalf("Error decoding base64 key:%s", err)
			return 1
		}
		unsealKeysBins = append(unsealKeysBins, tmpBin)
	}
	var masterKey []byte
	if len(unsealKeysBins) > 1 {
		masterKey, err = shamir.Combine(unsealKeysBins)
		if err != nil {
			log.Fatalf("failed to generate key from shares: %s", err)
		}
	} else {
		masterKey = unsealKeysBins[0]
	}
	log.Debugf("Master key: %s", base64.StdEncoding.EncodeToString(masterKey))

	//Read keyring and decrypt it
	keyRingBin, err := getStorageValue(*keyRingPath)
	if err != nil {
		log.Fatalf("failed to read file: %s", err)
		return 1
	}
	keyRingJSON, err := decryptTarget(keyRingBin.binValue, masterKey, "core/keyring")

	if err != nil {
		log.Fatalf("Error decrypting Keyring:%s", err)
		return 1
	}
	log.Debugf("Keyring:%s", keyRingJSON)
	keyring, err := DeserializeKeyring(keyRingJSON)
	if err != nil {
		log.Fatalf("failed to deserialize keyring: %s", err)
	}

	log.Debugf("Keyring deserialized:%s", spew.Sdump(keyring))

	//Decrypt with keyring
	cipherBin, err := getStorageValue(*encryptedKeyPath)
	if err != nil {
		log.Fatalf("failed to read file: %s", err)
		return 1
	}
	clear, err := decryptWithKeyring(keyring, cipherBin.binValue, cipherBin.Key)
	if err != nil {
		log.Fatalf("failed to read file: %s", err)
		return 1
	}
	log.Infof("Decrypted data:%s", spew.Sdump(clear))

	var prettyJSON bytes.Buffer
	error := json.Indent(&prettyJSON, clear, "", "\t")
	if error != nil {
		log.Println("JSON parse error: ", error)
		return 1
	}

	fmt.Printf("%s", prettyJSON.String())
	return 0

}

func main() {
	os.Exit(main_())
}
