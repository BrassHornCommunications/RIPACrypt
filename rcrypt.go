package main

import (
	"bytes"
	"crypto"
	"encoding/json"
	"flag"
	"fmt"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"strings"
	"time"
)

// CoreConf describes a users configuration file
type CoreConf struct {
	UseTor      bool   `json:"usetor"`
	UserID      uint64 `json:"userid"`
	BTCAddr     string `json:"btcaddr"`
	PublicKey   string `json:"public_key"`
	PrivateKey  string `json:"private_key"`
	Fingerprint string `json:"fingerprint"`
}

const (
	// RIPACRYPTURL is the base URL for all queries
	RIPACRYPTURL = "https://ripacrypt.download/1/"

	// CLIENTVERSION is not currently used but useful to have
	CLIENTVERSION = "1.0.0"

	// TORSOCKS defines the SOCKS5 host we use if a user wants to use Tor
	TORSOCKS = "localhost:9050"
)

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func main() {

	rand.Seed(time.Now().UnixNano())

	// Register
	// Creates a new account on the RIPACrypt platform with a public GPG key.
	// If a public key is not provided then a public private GPG key pair is generated (the recommended default)
	registerCommand := flag.NewFlagSet("register", flag.ExitOnError)
	publicKeyFlag := registerCommand.String("publickey", "", "Path to the GPG public key to register")
	useTorToRegister := registerCommand.Bool("usetor", false, "Enforce use of Tor SOCKS5 proxy")
	username := registerCommand.String("name", "Anonymous", "Your name (we recommend against setting this)")
	comment := registerCommand.String("comment", "", "A comment to add to your GPG key (we recommend against setting this)")
	email := registerCommand.String("email", "", "The 'email' address for your GPG key (we recommend against setting this)")
	debugRegister := registerCommand.Bool("debug", false, "See full JSON API response")

	// New Crypt
	// Stores data in a new crypt.
	// Unless overridden bu the -isencrypted flag data will be encrypted with the GPG public key before upload
	// The -checkinduration and -misscount flags will define how long a crypt can live before being destroyed
	newCommand := flag.NewFlagSet("new", flag.ExitOnError)
	dataToStoreFlag := newCommand.String("data", "", "Path to the plaintext you wish to encrypt and store in a crypt (or STDIN)")
	preEncryptedFlag := newCommand.Bool("isencrypted", false, "Is data already encrypted?")
	useTorForNew := newCommand.Bool("usetor", false, "Enforce use of Tor SOCKS5 proxy")
	descriptionFlag := newCommand.String("description", "", "A description of the crypt (be careful!)")
	checkInDurationFlag := newCommand.Int64("checkinduration", 86400, "Minimum time in seconds allowed between checkins")
	missCountFlag := newCommand.Int64("misscount", 3, "Maximim number of check-ins allowed before the crypt is destroyed")
	debugNewCrypt := newCommand.Bool("debug", false, "See full JSON API response")

	// Checkin TODO
	// Performs a "check in" which will reset the clock on a crypts self-destruction
	checkinCommand := flag.NewFlagSet("checkin", flag.ExitOnError)
	cryptIDFlag := checkinCommand.String("crypt", "", "ID of the crypt")
	useTorToCheckin := checkinCommand.Bool("usetor", false, "Enforce use of Tor SOCKS5 proxy")
	debugCheckin := checkinCommand.Bool("debug", false, "See full JSON API response")

	// Challenge
	// All write actions on RIPACrypt require the decryption of a challenge text which is sent by the server.
	// This challenge is encrypted with the users public key.
	// The API endpoint is publicly available so we might as well make it available to the client too.
	challengeCommand := flag.NewFlagSet("getchallenge", flag.ExitOnError)
	useTorForChallenge := challengeCommand.Bool("usetor", false, "Enforce use of Tor SOCKS5 proxy")
	decryptChallenge := challengeCommand.Bool("decrypt", false, "Decrypt the challenge and display the cleartext")
	debugChallenge := challengeCommand.Bool("debug", false, "See full JSON API response")

	// NewBTC
	// Ideally each transaction one makes with bitcoin should be to a new address
	// to foil correlation. When adding more storage to your account (or to donate
	// you should generate a new bitcoin address each time.
	newBTCCommand := flag.NewFlagSet("newbtc", flag.ExitOnError)
	useTorForNewBTC := newBTCCommand.Bool("usetor", false, "Enforce use of Tor SOCKS5 proxy")
	debugNewBTC := newBTCCommand.Bool("debug", false, "See full JSON API response")

	// Destroy TODO
	// The MVP won't include an explicit destroy call

	//Grab what the user wants to do
	if len(os.Args) == 1 {
		fmt.Println("usage: ripacrypt <command> [<args>]")
		fmt.Println("The most commonly used commands are: ")
		fmt.Println(" register \t\tRegister a new crypto key pair")
		fmt.Println(" new \t\t\tCreate a new crypt")
		fmt.Println(" checkin \t\tKeep a crypt alive")
		fmt.Println(" destroy \t\tDestroys a crypt immediately")
		fmt.Println(" getchallenge \t\tRequest an encrypted challenge")
		fmt.Println(" newbtc \t\tGenerate a new Bitcoin address for your account")
		return
	}

	conf := readConfig()

	switch os.Args[1] {
	case "register":
		registerCommand.Parse(os.Args[2:])
	case "new":
		newCommand.Parse(os.Args[2:])
	case "checkin":
		checkinCommand.Parse(os.Args[2:])
	case "getchallenge":
		challengeCommand.Parse(os.Args[2:])
	case "newbtc":
		newBTCCommand.Parse(os.Args[2:])
	default:
		fmt.Printf("%q is not valid command.\n", os.Args[1])
		os.Exit(2)
	}

	// Register -----------------------------------------------------------------
	if registerCommand.Parsed() {

		//Check we're not about to overwrite our config!
		if conf.UserID != 0 {
			fmt.Println("Your config file indicates a userid is already registered. Please check ~/.ripacrypt/rc.conf")
			return
		}

		var PublicKey, PrivateKey, PublicKeyFingerprint string
		if *publicKeyFlag == "" {
			fmt.Println("No public key passed - generating our own one")
			var newEmail string

			if *email == "" {
				newEmail = RandStringRunes(24) + "@clients.ripacrypt.download"
			} else {
				newEmail = *email
			}
			packetConf := packet.Config{DefaultHash: crypto.SHA256}
			pgpEntity, pgpGenErr := openpgp.NewEntity(*username, *comment, newEmail, &packetConf)
			if pgpGenErr != nil {
				fmt.Println("There was an error generating a new GPG key for you")
				fmt.Println(pgpGenErr)
			}
			fmt.Println("Signing identities")
			for _, id := range pgpEntity.Identities {
				err := id.SelfSignature.SignUserId(id.UserId.Id, pgpEntity.PrimaryKey, pgpEntity.PrivateKey, nil)
				if err != nil {
					fmt.Println(err)
					return
				}

				id.SelfSignature.PreferredHash = []uint8{8}
			}
			fmt.Println(pgpEntity.PrimaryKey.KeyIdString() + " " + newEmail)
			privBuf := new(bytes.Buffer)
			pubBuf := new(bytes.Buffer)
			w1, err1 := armor.Encode(pubBuf, openpgp.PublicKeyType, nil)
			w2, err2 := armor.Encode(privBuf, openpgp.PrivateKeyType, nil)
			if err1 != nil || err2 != nil {
				fmt.Println(err1)
				fmt.Println(err2)
				return
			}

			pgpEntity.SerializePrivate(w2, nil)
			w2.Close()

			pgpEntity.Serialize(w1)
			w1.Close()

			PublicKey = pubBuf.String()
			PrivateKey = privBuf.String()
			fmt.Println(PublicKey)

			fingerprint, publicKeyErr := VerifyGPGPublicKey(PublicKey)
			if publicKeyErr != nil {
				fmt.Println("There was an error validating the generated public key")
				fmt.Println(publicKeyErr)
				return
			}
			PublicKeyFingerprint = fingerprint
			fmt.Println("Successfully created your Public Key with fingerprint ", PublicKeyFingerprint)
		} else {
			b, fileReadErr := ioutil.ReadFile(*publicKeyFlag)
			if fileReadErr != nil {

				fmt.Println("There was an error processing your public key")
				fmt.Println(fileReadErr)
			}

			PublicKey = string(b)
			fingerprint, publicKeyErr := VerifyGPGPublicKey(PublicKey)

			if publicKeyErr != nil {
				fmt.Println("There was an error processing your public key")
				fmt.Println(publicKeyErr)
				return
			}
			PublicKeyFingerprint = fingerprint
			fmt.Println("Successfully parsed your Public Key with fingerprint ", PublicKeyFingerprint)
		}

		//Public key stuff is complete, let's continue

		if *useTorToRegister == true || conf.UseTor == true {
			conf.UseTor = true
		}

		apiResponse, registerErr := RIPACryptRegister(PublicKey, conf.UseTor)

		if registerErr != nil {
			fmt.Println("There was an error processing your registration;")
			fmt.Println(registerErr)
		} else {

			fmt.Println("Your user id is: ", apiResponse.UserID)
			fmt.Println("Your unique Bitcoin address is: ", apiResponse.BTCAddr)
			conf.UserID = apiResponse.UserID
			conf.BTCAddr = apiResponse.BTCAddr
			conf.PublicKey = PublicKey
			conf.PrivateKey = PrivateKey
			conf.Fingerprint = PublicKeyFingerprint

			if *debugRegister == true {
				debugBuffer, jsonMarshalErr := json.Marshal(apiResponse)

				if jsonMarshalErr == nil {
					fmt.Println(string(debugBuffer))
				} else {
					fmt.Println("There was an error transforming the api response to a JSON entity")
				}
			}

			configFileBuffer, jsonMarshalErr := json.Marshal(conf)
			if jsonMarshalErr != nil {
				fmt.Println("There was an error parsing an internal data structure to write a new config file")
				fmt.Println(jsonMarshalErr)
				return
			}

			mkDirErr := os.Mkdir(os.Getenv("HOME")+"/.ripacrypt/", 0700)

			if mkDirErr != nil {
				if strings.Contains(mkDirErr.Error(), "file exists") == false {
					fmt.Println("There was an error attempting to create ~/.ripacrypt/ to store your config")
					fmt.Println(mkDirErr)
					return
				}
			}
			writeConfigFileErr := ioutil.WriteFile(os.Getenv("HOME")+"/.ripacrypt/rc.conf", configFileBuffer, 0644)

			if writeConfigFileErr != nil {
				fmt.Println("There was an error attempting to write your config file to disk")
				fmt.Println(writeConfigFileErr)
				return
			}

		}
	}

	// New Crypt ----------------------------------------------------------------
	if newCommand.Parsed() {
		var dataToStore string

		if *dataToStoreFlag == "" {
			stat, _ := os.Stdin.Stat()
			if (stat.Mode() & os.ModeCharDevice) == 0 {
				fmt.Println("data is being piped to stdin")
				stdInBytes, _ := ioutil.ReadAll(os.Stdin)
				dataToStore = string(stdInBytes)
			} else {
				fmt.Println("Please supply the path to the data that is required to be stored")
				return
			}
		} else {
			//Lets read the data
			b, err := ioutil.ReadFile(*dataToStoreFlag)
			if err != nil {
				fmt.Println("There was an error parsing our data")
				fmt.Println(err)
				return
			}
			dataToStore = string(b)
		}

		if conf.UserID == 0 {
			fmt.Println("Your config file doesn't contain a userID - crypts cannot be created")
			return
		}

		if *useTorForNew == true || conf.UseTor == true {
			fmt.Println("Using Tor to register a new crypt")
			conf.UseTor = true
		} else {
			fmt.Println("Connecting directly to create a new crypt")
		}
		//NewCrypt(dataToStore string, UserID uint64, Description string, CheckInDuration int, MissCount int, UseTor bool, IsEncrypted bool)

		apiResponse, newErr := NewCrypt(dataToStore, *descriptionFlag, *checkInDurationFlag, *missCountFlag, *preEncryptedFlag, conf)

		if newErr != nil {
			fmt.Println("There was an issue creating your crypt")
			fmt.Println(newErr)
		} else {
			fmt.Println("Your CryptID is: ", apiResponse.CryptPayload.CryptID)

			if *debugNewCrypt == true {
				debugBuffer, jsonMarshalErr := json.Marshal(apiResponse)

				if jsonMarshalErr == nil {
					fmt.Println(string(debugBuffer))
				} else {
					fmt.Println("There was an error transforming the api response to a JSON entity")
				}
			}

		}
	}

	//Challenge
	if challengeCommand.Parsed() {
		if *useTorForChallenge == true || conf.UseTor == true {
			fmt.Println("Using Tor to request a challenge")
			conf.UseTor = true
		} else {
			fmt.Println("Connecting directly to request a challenge")
		}

		apiResponse, challengeErr := GetChallenge(conf.UserID, conf.Fingerprint, conf.UseTor)

		if challengeErr != nil {
			fmt.Println("There was an issue getting the challenge")
			fmt.Println(challengeErr)
		} else {
			fmt.Println("Your encrypted challenge is: ", apiResponse.Challenge)
		}

		if *decryptChallenge == true {
			fmt.Println("Decrypting...")
			cleartext, err := DecryptChallenge(apiResponse.Challenge, conf.PrivateKey)

			if err != nil {
				fmt.Println("There was an error decrypting the challenge;")
				fmt.Println(err)
			} else {
				fmt.Println("The cleartext challenge is: ", cleartext)
			}
		}

		if *debugChallenge == true {
			debugBuffer, jsonMarshalErr := json.Marshal(apiResponse)

			if jsonMarshalErr == nil {
				fmt.Println(string(debugBuffer))
			} else {
				fmt.Println("There was an error transforming the api response to a JSON entity")
			}
		}

	}

	// New BTC -------------------------------------------------------------------
	if newBTCCommand.Parsed() {
		if *useTorForNewBTC == true || conf.UseTor == true {
			fmt.Println("Using Tor to request a new bitcoin address")
			conf.UseTor = true
		} else {
			fmt.Println("Connecting directly to request a new bitcoin address")
		}

		apiResponse, newBTCErr := GetBTC(conf)

		if newBTCErr != nil {
			fmt.Println("There was an issue getting a new bitcoin address")
			fmt.Println(newBTCErr)
		} else {
			fmt.Println("Your new bitcoin address is: ", apiResponse.BTCAddr)

			if *debugNewBTC == true {
				debugBuffer, jsonMarshalErr := json.Marshal(apiResponse)

				if jsonMarshalErr == nil {
					fmt.Println(string(debugBuffer))
				} else {
					fmt.Println("There was an error transforming the api response to a JSON entity")
				}
			}

		}
	}

	// Checkin ------------------------------------------------------------------
	if checkinCommand.Parsed() {
		if *cryptIDFlag == "" {
			fmt.Println("Cannot checkin without specifying a crypt id")
			fmt.Println("Use -crypt=CRYPTID")
			return
		}

		if *useTorToCheckin == true || conf.UseTor == true {
			fmt.Println("Using Tor to checkin with crypt " + *cryptIDFlag)
			conf.UseTor = true
		} else {
			fmt.Println("Connecting directly to checkin with crypt " + *cryptIDFlag)
		}

		apiResponse, checkinErr := Checkin(conf, *cryptIDFlag)

		if checkinErr != nil {
			fmt.Println("There was an issue checking in with that crypt")
			fmt.Println(checkinErr)
		} else {
			fmt.Println(apiResponse.Message)
			if *debugCheckin == true {
				debugBuffer, jsonMarshalErr := json.Marshal(apiResponse)

				if jsonMarshalErr == nil {
					fmt.Println(string(debugBuffer))
				} else {
					fmt.Println("There was an error transforming the api response to a JSON entity")
				}
			}

		}
	}

}

func readConfig() CoreConf {
	var conf CoreConf
	filename := os.Getenv("HOME") + "/.ripacrypt/rc.conf"

	b, err := ioutil.ReadFile(filename)

	if err != nil {
		log.Println("Cannot read configuration file using defaults", filename)
		conf.UseTor = false
	} else {
		err = json.Unmarshal(b, &conf)

		if err != nil {
			log.Fatal("Cannot parse configuration file ", filename)
		}
	}
	return conf
}
