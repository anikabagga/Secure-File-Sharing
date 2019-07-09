package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (

	// You neet to add with
	// go get github.com/nweaver/cs161-p2/userlib
	"github.com/nweaver/cs161-p2/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var key *userlib.PrivateKey
	key, _ = userlib.GenerateRSAKey()
	userlib.DebugMsg("Key is %v", key)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// The structure for a KeyLink that stores the FileMeta location and associated
// Encryption Key
type KeyLink struct {
	DSMetaLocation string //this should be a UUID
	FileEncryptionKey []byte
	HMACKey []byte
}

// The structure definition for a user record
type User struct {
	Username string
	DSKey []byte
	EncryptKey []byte
	HMACKey []byte
	FileKeyChain map[string]KeyLink //stores keys by filename
	RSAprivKey *userlib.PrivateKey
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

// The structure for file metadata
type FileMeta struct {
	Owner []byte //RSA encrypted username of owner
	Numofparts int
}

// The structure for file
type File struct {
	Data []byte
}

//CFB Encrypt Helper function
func AESCFBEncrypt(key []byte, data []byte) []byte {
	enc_bytearray := make([]byte, userlib.BlockSize + len(data))
	iv := enc_bytearray[:userlib.BlockSize]
	copy(iv, userlib.RandomBytes(16))
	cipher := userlib.CFBEncrypter(key, iv)
	cipher.XORKeyStream(enc_bytearray[userlib.BlockSize:], data)
	return enc_bytearray
}

//CFB Decrypt Helper function.
func AESCFBDecrypt(key []byte, data []byte) {
	cipher := userlib.CFBDecrypter(key, data[:userlib.BlockSize])
	cipher.XORKeyStream(data[userlib.BlockSize:], data[userlib.BlockSize:])
}

//Helper for generating HMAC. Returns computed HMAC tag
func GenerateHMAC(key []byte, data []byte) []byte {
	hmac := userlib.NewHMAC(key)
	hmac.Write(data)
	tag := hmac.Sum([]byte(""))
	return tag
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
/*
	MUST take the user’s password, which is assumed to have good entropy, and use
	this to help populate the User data structure (including generating at least one random RSA key),
	securely store a copy of the data structure in the data store, register a public key in
	the keystore, and return the newly populated user data structure. The user’s name
	MUST be confidential to the data store.
*/

	//generate random RSA key
	rsa_privatekey, _ := userlib.GenerateRSAKey()
	rsa_publickey := rsa_privatekey.PublicKey

	//register public key in keystore
	userlib.KeystoreSet(username, rsa_publickey)

	//populate date structure
	userdata.Username = username
	userdata.DSKey = userlib.Argon2Key([]byte(password), []byte(username), uint32(len(username)))
	userdata.EncryptKey = userlib.Argon2Key([]byte(password), []byte(username), uint32(userlib.BlockSize))
	userdata.HMACKey = userlib.Argon2Key([]byte(password), []byte(username), uint32(userlib.HashSize))
	userdata.FileKeyChain = make(map[string]KeyLink)
	userdata.RSAprivKey = rsa_privatekey

	//Marshal to JSON
	userdata_marshaled, _ := json.Marshal(userdata)
	//encrypt userdata using CFBEncrypt
	userdata_CFBencrypted := AESCFBEncrypt(userdata.EncryptKey, userdata_marshaled)

	//Generate HMAC
	userdata_tag := GenerateHMAC(userdata.HMACKey, userdata_CFBencrypted)

	//Append HMAC tag to end of Ciphertext
	AES_CFB_HMAC_usercipher := append(userdata_CFBencrypted, userdata_tag...)

	//Store secure copy of userdata to datastore_key
	userlib.DatastoreSet(string(userdata.DSKey), AES_CFB_HMAC_usercipher)

	return &userdata, err
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	/*
	if the username and password are correct this MUST load the appropriate information
	from the data store to populate the User data structure or, if the data is corrupted,
	return an error. If either the username or password are not correct it MUST return an error.
	You MAY return an error that does not distinguish between a bad username, bad
	password, or corrupted data
	*/

	var userdata User
	//First test if username and password is valid
	_, success := userlib.KeystoreGet(username)

	if !success {
		return nil, errors.New("Not a valid user")
	}

	dskey := userlib.Argon2Key([]byte(password), []byte(username), uint32(len(username)))
	encryptkey := userlib.Argon2Key([]byte(password), []byte(username), uint32(userlib.BlockSize))
	hmackey := userlib.Argon2Key([]byte(password), []byte(username), uint32(userlib.HashSize))
	AES_CFB_HMAC_cipher, success := userlib.DatastoreGet(string(dskey))

	//Test if password is correct
	if !success {
		return nil, errors.New("Password is Incorrect")
	}

	//get encrypted data and HMAC
	encrypted_user := AES_CFB_HMAC_cipher[:(len(AES_CFB_HMAC_cipher) - userlib.HashSize)]
	hmac := AES_CFB_HMAC_cipher[(len(AES_CFB_HMAC_cipher) - userlib.HashSize):]

	//Compute HMAC for comparison
	tag := GenerateHMAC(hmackey, encrypted_user)
	if !userlib.Equal(hmac, tag) {
		return nil, errors.New("IntegrityError: Data is Corrupted")
	}

	//Decrypt and unmarshal
	AESCFBDecrypt(encryptkey, encrypted_user)
	if err := json.Unmarshal(encrypted_user[userlib.BlockSize:], &userdata); err != nil {
		return nil, errors.New("Json Umarshal corrupted")
	}

	return &userdata, err
}

// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	//Generate DataStore Key for File Metadata
	metaDSKey := uuid.New().String()
	//Test if there is a pre-existing record in the Datastore
	/*rec, _ := userlib.DatastoreGet(metaDSKey)
	if rec != nil {
		return errors.New("Cannot overwrite object in Datastore")
	}*/

	//Generate Ecryption Key for File
	fileEncryptKey := userlib.Argon2Key([]byte(uuid.New().String()), userlib.RandomBytes(16), uint32(userlib.BlockSize))
	//Generate HMAC Key for File
	fileHMACKey := userlib.Argon2Key([]byte(uuid.New().String()), userlib.RandomBytes(16), uint32(userlib.HashSize))

	//Create File MetaData and set owner
	partnum := 1
	userpubkey, _ := userlib.KeystoreGet(userdata.Username)
	owner_rsaencrypted, _ := userlib.RSAEncrypt(&userpubkey, []byte(userdata.Username), []byte(userdata.Username))
	fileMeta := FileMeta{owner_rsaencrypted, partnum}

	//Create File Structure and populate Data. Since it's a new file there is only 1 part
	fileDSKey := userlib.Argon2Key([]byte(metaDSKey + string(partnum)), []byte(metaDSKey), uint32(len(metaDSKey)))
	file := File{data}

	//Marshal and Encrpyt
	metadata_marshaled, _ := json.Marshal(fileMeta)
	file_marshaled, _ := json.Marshal(file)
	CFB_metadata := AESCFBEncrypt(fileEncryptKey, metadata_marshaled)
	CFB_file := AESCFBEncrypt(fileEncryptKey, file_marshaled)

	//Generate HMAC
	AES_CFB_HMAC_metadata := append(CFB_metadata, GenerateHMAC(fileHMACKey, CFB_metadata)...)
	AES_CFB_HMAC_file := append(CFB_file, GenerateHMAC(fileHMACKey, CFB_file)...)

	//Store Cipher of Meta and File in DataStore
	userlib.DatastoreSet(string(metaDSKey), AES_CFB_HMAC_metadata)
	userlib.DatastoreSet(string(fileDSKey), AES_CFB_HMAC_file)

	//Add metadata info to user's FileKeyChain
	userdata.FileKeyChain[filename] = KeyLink{metaDSKey, fileEncryptKey, fileHMACKey}

	//Add updated userdata back to datastore
	userdata_marshaled, _ := json.Marshal(userdata)
	userdata_CFBencrypted := AESCFBEncrypt(userdata.EncryptKey, userdata_marshaled)
	userdata_tag := GenerateHMAC(userdata.HMACKey, userdata_CFBencrypted)
	AES_CFB_HMAC_usercipher := append(userdata_CFBencrypted, userdata_tag...)
	userlib.DatastoreSet(string(userdata.DSKey), AES_CFB_HMAC_usercipher)

}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	var filemeta FileMeta

	//retreive file metadata
	keylink := userdata.FileKeyChain[filename]
	aescfbhmac_meta, _ := userlib.DatastoreGet(keylink.DSMetaLocation)

	//check hmac and decrypt file metadata
	cfbencrypted_meta := aescfbhmac_meta[:(len(aescfbhmac_meta) - userlib.HashSize)]
	meta_hmac := aescfbhmac_meta[(len(aescfbhmac_meta) - userlib.HashSize):]
	computed_htag := GenerateHMAC(keylink.HMACKey,cfbencrypted_meta)

	if !userlib.Equal(meta_hmac, computed_htag){
		return errors.New("IntegrityError: Metadata is Corrupted")
	}

	AESCFBDecrypt(keylink.FileEncryptionKey, cfbencrypted_meta)
	if err := json.Unmarshal(cfbencrypted_meta[userlib.BlockSize:], &filemeta); err != nil {
		return errors.New("Json Umarshal corrupted")
	}

	//populate new file structure
	fileDSKey := userlib.Argon2Key([]byte(keylink.DSMetaLocation + string(filemeta.Numofparts + 1)), []byte(keylink.DSMetaLocation), uint32(len(keylink.DSMetaLocation)))
	file := File{data}
	//marshal file struct, encrypt, hmac and store in datastore
	file_marshaled, _ := json.Marshal(file)
	CFB_file := AESCFBEncrypt(keylink.FileEncryptionKey, file_marshaled)
	AES_CFB_HMAC_file := append(CFB_file, GenerateHMAC(keylink.HMACKey, CFB_file)...)
	userlib.DatastoreSet(string(fileDSKey), AES_CFB_HMAC_file)

	//increment count on file metadata
	filemeta.Numofparts = filemeta.Numofparts + 1
	//encrypt updated file metadata and store in datastore
	metadata_marshaled, _ := json.Marshal(filemeta)
	cfbencrypted_meta = AESCFBEncrypt(keylink.FileEncryptionKey, metadata_marshaled)
	AES_CFB_HMAC_metadata := append(cfbencrypted_meta, GenerateHMAC(keylink.HMACKey, cfbencrypted_meta)...)
	userlib.DatastoreSet(keylink.DSMetaLocation, AES_CFB_HMAC_metadata)

	return err
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	var filemeta FileMeta
	var combineddata []byte

	//retreive file metadata
	keylink := userdata.FileKeyChain[filename]
	aescfbhmac_meta, success := userlib.DatastoreGet(keylink.DSMetaLocation)
	if !success {
		return nil, errors.New("File Does Not Exist")
	}

	//check hmac and decrypt file metadata
	cfbencrypted_meta := aescfbhmac_meta[:(len(aescfbhmac_meta) - userlib.HashSize)]
	meta_hmac := aescfbhmac_meta[(len(aescfbhmac_meta) - userlib.HashSize):]
	computed_htag := GenerateHMAC(keylink.HMACKey,cfbencrypted_meta)

	if !userlib.Equal(meta_hmac, computed_htag){
		return nil, errors.New("IntegrityError: Metadata is Corrupted")
	}

	AESCFBDecrypt(keylink.FileEncryptionKey, cfbencrypted_meta)
	if err := json.Unmarshal(cfbencrypted_meta[userlib.BlockSize:], &filemeta); err != nil {
		return nil, errors.New("Json Umarshal corrupted")
	}

	//loop through appended files, check hmac, decrpyt, unmarshal and append to &data
	for i := 1; i <= filemeta.Numofparts; i++ {
		var file File
		fileDSKey := userlib.Argon2Key([]byte(keylink.DSMetaLocation + string(i)), []byte(keylink.DSMetaLocation), uint32(len(keylink.DSMetaLocation)))
		//retreive file from DataStore
		aescfbhmac_file, _ := userlib.DatastoreGet(string(fileDSKey))
		cfbencrypted_file := aescfbhmac_file[:(len(aescfbhmac_file) - userlib.HashSize)]
		file_hmac := aescfbhmac_file[(len(aescfbhmac_file) - userlib.HashSize):]
		computed_htag := GenerateHMAC(keylink.HMACKey,cfbencrypted_file)

		if !userlib.Equal(file_hmac, computed_htag){
			return nil, errors.New("IntegrityError: Data is Corrupted")
		}
		AESCFBDecrypt(keylink.FileEncryptionKey, cfbencrypted_file)
		if err := json.Unmarshal(cfbencrypted_file[userlib.BlockSize:], &file); err != nil {
			return nil, errors.New("Json Umarshal corrupted")
		}

		combineddata = append(combineddata, file.Data...)
	}

	return combineddata, err
}

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
	RSASignature []byte
	DSMetaLocation []byte
	SharedKey []byte //this includes hmac
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string) (
	msgid string, err error) {
	//Check Keystore if recipient is valid, if not error
	recipient_pubkey, success := userlib.KeystoreGet(recipient)
	if !success {
		return "", errors.New("Recipient is Invalid")
	}

	keylink := userdata.FileKeyChain[filename]
	//concatenate [encryptionkey||hmackey]
	filekeyhmac := append(keylink.FileEncryptionKey, keylink.HMACKey...)
	//Find AES CFB Key for file, marshal and encrypt
	filekey_marshaled, _ := json.Marshal(filekeyhmac)
	rsaencrpyted_key, err := userlib.RSAEncrypt(&recipient_pubkey, filekey_marshaled, []byte(userdata.Username))

	//Populate new share record including RSA signature using recipient pubkey and
	//encrypt file's aes cfb key using RSAEncrypt
	rec_rsasig, err := userlib.RSASign(userdata.RSAprivKey, rsaencrpyted_key)
	sharerecord := sharingRecord{rec_rsasig, []byte(keylink.DSMetaLocation), rsaencrpyted_key}

	//marshal the share record, generate Share ID and store in DataStore, return ShareRecID
	//uuid's are almost gauranteed to be unique
	sharerec_marshaled, _ := json.Marshal(sharerecord)
	sharerecID := uuid.New().String()
	userlib.DatastoreSet(sharerecID, sharerec_marshaled)

	return sharerecID, err
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	msgid string) error {

	sender_pubkey, success := userlib.KeystoreGet(sender)
	//Validate sender
	if !success {
		return errors.New("Sender is Invalid")
	}

	//retreive Share Record from Datastore and validate
	sharerec_marshaled, success := userlib.DatastoreGet(msgid)
	if !success {
		return errors.New("File Share Does Not Exist")
	}

	//unmarshal share record and verify RSA Signature using privatekey
	var sharerecord sharingRecord
	if err := json.Unmarshal(sharerec_marshaled, &sharerecord); err != nil {
		return errors.New("Share Record Unmarshal Failed")
	}
	err := userlib.RSAVerify(&sender_pubkey, sharerecord.SharedKey, sharerecord.RSASignature)
	//decrypt key using RSA decrypt and unmarshal
	sharekey_marshaled, err := userlib.RSADecrypt(userdata.RSAprivKey, sharerecord.SharedKey, []byte(sender))
	var filekeyhmac []byte
	if err := json.Unmarshal(sharekey_marshaled, &filekeyhmac); err != nil {
		return errors.New("Shared Key Unmarshal Failed")
	}

	sharekey := filekeyhmac[:(len(filekeyhmac) - userlib.HashSize)]
	hmackey := filekeyhmac[(len(filekeyhmac) - userlib.HashSize):]
	//Create KeyLink, associate sharedkey with recipient's filename and add to FileKeyChain
	userdata.FileKeyChain[filename] = KeyLink{string(sharerecord.DSMetaLocation), sharekey, hmackey}

	//Add updated userdata back to datastore
	userdata_marshaled, _ := json.Marshal(userdata)
	userdata_CFBencrypted := AESCFBEncrypt(userdata.EncryptKey, userdata_marshaled)
	userdata_tag := GenerateHMAC(userdata.HMACKey, userdata_CFBencrypted)
	AES_CFB_HMAC_usercipher := append(userdata_CFBencrypted, userdata_tag...)
	userlib.DatastoreSet(string(userdata.DSKey), AES_CFB_HMAC_usercipher)

	return err
}

// Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {
	//retreive the current encryption key and hmac key
	keylink := userdata.FileKeyChain[filename]
	current_fkey := keylink.FileEncryptionKey
	current_hkey := keylink.HMACKey

	//retreive the file meta data and decrypt
	aescfbhmac_meta, success := userlib.DatastoreGet(keylink.DSMetaLocation)
	if !success {
		return errors.New("File Does Not Exist")
	}
	cfbencrypted_meta := aescfbhmac_meta[:(len(aescfbhmac_meta) - userlib.HashSize)]
	meta_hmac := aescfbhmac_meta[(len(aescfbhmac_meta) - userlib.HashSize):]
	computed_htag := GenerateHMAC(current_hkey,cfbencrypted_meta)

	if !userlib.Equal(meta_hmac, computed_htag){
		return errors.New("IntegrityError: Metadata is Corrupted")
	}
	var filemeta FileMeta
	AESCFBDecrypt(current_fkey, cfbencrypted_meta)
	if err := json.Unmarshal(cfbencrypted_meta[userlib.BlockSize:], &filemeta); err != nil {
		return errors.New("Json Umarshal corrupted")
	}
	numofparts := filemeta.Numofparts

	//Verify Owner of File
	owner, err := userlib.RSADecrypt(userdata.RSAprivKey, filemeta.Owner, []byte(userdata.Username))
	if string(owner) != userdata.Username {
		return errors.New("Only the File Onwer can Revoke")
	}

	//generate new encryption and hmac keys
	fileEncryptKey := userlib.Argon2Key([]byte(uuid.New().String()), userlib.RandomBytes(16), uint32(userlib.BlockSize))
	fileHMACKey := userlib.Argon2Key([]byte(uuid.New().String()), userlib.RandomBytes(16), uint32(userlib.HashSize))

	//encrypt metadata using new keys and store
	metadata_marshaled, _ := json.Marshal(filemeta)
	CFB_metadata := AESCFBEncrypt(fileEncryptKey, metadata_marshaled)
	AES_CFB_HMAC_metadata := append(CFB_metadata, GenerateHMAC(fileHMACKey, CFB_metadata)...)
	userlib.DatastoreSet(keylink.DSMetaLocation, AES_CFB_HMAC_metadata)

	//iterate through all the file parts, decrypt and re-encrypt using new keys and store
	for i := 1; i <= numofparts; i++ {
		fileDSKey := userlib.Argon2Key([]byte(keylink.DSMetaLocation + string(i)), []byte(keylink.DSMetaLocation), uint32(len(keylink.DSMetaLocation)))
		//retreive file from DataStore
		aescfbhmac_file, _ := userlib.DatastoreGet(string(fileDSKey))
		cfbencrypted_file := aescfbhmac_file[:(len(aescfbhmac_file) - userlib.HashSize)]
		file_hmac := aescfbhmac_file[(len(aescfbhmac_file) - userlib.HashSize):]
		computed_htag := GenerateHMAC(current_hkey,cfbencrypted_file)

		if !userlib.Equal(file_hmac, computed_htag){
			return errors.New("IntegrityError: Data is Corrupted")
		}
		AESCFBDecrypt(current_fkey, cfbencrypted_file)

		//encrypt using new key and store
		cfbencrypted_file = AESCFBEncrypt(fileEncryptKey, cfbencrypted_file)
		//hmac
		aescfbhmac_file = append(cfbencrypted_file, GenerateHMAC(fileHMACKey, cfbencrypted_file)...)
		userlib.DatastoreSet(string(fileDSKey), aescfbhmac_file)
	}

	//Add metadata info to user's FileKeyChain
	userdata.FileKeyChain[filename] = KeyLink{keylink.DSMetaLocation, fileEncryptKey, fileHMACKey}

	//Add updated userdata back to datastore
	userdata_marshaled, _ := json.Marshal(userdata)
	userdata_CFBencrypted := AESCFBEncrypt(userdata.EncryptKey, userdata_marshaled)
	userdata_tag := GenerateHMAC(userdata.HMACKey, userdata_CFBencrypted)
	AES_CFB_HMAC_usercipher := append(userdata_CFBencrypted, userdata_tag...)
	userlib.DatastoreSet(string(userdata.DSKey), AES_CFB_HMAC_usercipher)


	return err
}
