package assn1

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (

	// You neet to add with
	// go get github.com/fenilfadadu/CS628-assn1/userlib
	//"crypto/cipher"

	"github.com/fenilfadadu/CS628-assn1/userlib"

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

// The structure definition for a user record
type User struct {
	Username string
	Key      userlib.PrivateKey
	//for accessing filelist
	KeyForFileList          string
	SymmetricKeyForFileList []byte
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleard during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

//This will contain user data structure and its digest

type FileSegment struct {
	Data []byte
}

type SegmentStructure struct {
	SymmetricKeyforSegment []byte
	SegmentKey             string
}

//use wrapper here
type File struct {
	Segments []SegmentStructure
}

type FileStructure struct {
	SymmetricKey []byte
	Key          string
	Owner        bool
}

//use wrapper here
type FileList struct {
	//don't forget to initalize map
	Files map[string]FileStructure
}

type Wrapper struct {
	EncryptedData []byte
	Digest        []byte
}

func encryptData(msg []byte, Key []byte) []byte {
	//encrypting userdata
	ciphertext := make([]byte, userlib.BlockSize+len(msg))

	iv := ciphertext[:userlib.BlockSize]
	// take first 16 bytes of ArgonKey is iv
	copy(iv, userlib.RandomBytes(userlib.BlockSize)) //HERE IV
	cipher := userlib.CFBEncrypter(Key, iv)
	cipher.XORKeyStream(ciphertext[userlib.BlockSize:], []byte(msg))

	return ciphertext
	//cipher contain encrypted userdata
}

//be careful final data is in ciphertext[userlib.Blocksize:]
func decryptData(ciphertext []byte, Key []byte) []byte {
	//userlib.DebugMsg("-->%d", len(iv))
	iv := ciphertext[:userlib.BlockSize]
	cipher := userlib.CFBDecrypter(Key, iv) //HERE IV

	cipher.XORKeyStream(ciphertext[userlib.BlockSize:], ciphertext[userlib.BlockSize:])

	return ciphertext
}

func calculateHMAC(Key []byte, data []byte) []byte {
	mac := userlib.NewHMAC(Key)
	mac.Write(data)
	maca := mac.Sum(nil)
	return maca
}

// You can assume the user has a STRONG password
func InitUser(username string, password string) (userdataptr *User, err error) {

	var userdata User
	userdata.Username = username

	//Argon key generation for Key:Value pair
	ArgonKey := userlib.Argon2Key([]byte(password),
		[]byte(userdata.Username), 32)

	//Initialize fileList structure
	userdata.KeyForFileList = hex.EncodeToString(userlib.RandomBytes(32))

	//userdata.IVforFileList = userlib.RandomBytes(userlib.BlockSize)
	arr := userlib.RandomBytes(32)
	userdata.SymmetricKeyForFileList = make([]byte, len(arr))
	copy(userdata.SymmetricKeyForFileList, arr)

	var filelist FileList
	filelist.Files = make(map[string]FileStructure)
	data, _ := json.Marshal(filelist)
	data = encryptData(data, userdata.SymmetricKeyForFileList)
	data, _ = json.Marshal(data)
	var fileListWrapper Wrapper
	fileListWrapper.EncryptedData = data
	fileListWrapper.Digest = calculateHMAC(userdata.SymmetricKeyForFileList, data)
	data, _ = json.Marshal(fileListWrapper)
	userlib.DatastoreSet(userdata.KeyForFileList, data)

	//storing private and public keys
	key, kerr := userlib.GenerateRSAKey()
	if kerr != nil {
		return &userdata, kerr
	}
	//store private key in user data structure
	userdata.Key = *key
	//store pubkey in keyStore
	pubkey := key.PublicKey
	userlib.KeystoreSet(userdata.Username, pubkey)

	msg, _ := json.Marshal(userdata)
	ciphertext := encryptData(msg, ArgonKey)

	var UserWrapper Wrapper

	tempVar, _ := json.Marshal(ciphertext)
	UserWrapper.EncryptedData = tempVar

	//calculate HMAC with password as a key
	UserWrapper.Digest = calculateHMAC(ArgonKey, tempVar)

	//add this structure along with its key to datastore
	d, _ := json.Marshal(UserWrapper)
	userlib.DatastoreSet(hex.EncodeToString(ArgonKey), d)

	return &userdata, err
}

/* This fetches the user information from the Datastore.  It should
fail with an error if the user/password is invalid, or if the user
data was corrupted, or if the user can't be found.*/
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User

	//Argon key generation for Key:Value pair
	ArgonKey := userlib.Argon2Key([]byte(password), []byte(username), 32)

	value, exists := userlib.DatastoreGet(hex.EncodeToString(ArgonKey))

	if !exists {
		return &userdata, errors.New("login failed: either username/password incorrect or data currupted")
	}

	var UserWrapper Wrapper
	json.Unmarshal(value, &UserWrapper)

	//calculate and check HMAC
	maca := calculateHMAC(ArgonKey, UserWrapper.EncryptedData)
	if !userlib.Equal(maca, UserWrapper.Digest) {
		return &userdata, errors.New("Data is modified - HMAC is not same")
	}

	//decrypting userdata
	var ciphertext []byte
	json.Unmarshal(UserWrapper.EncryptedData, &ciphertext)

	ciphertext = decryptData(ciphertext, ArgonKey)

	json.Unmarshal(ciphertext[userlib.BlockSize:], &userdata)

	return &userdata, err
}

/* This stores a file in the datastore.
The name of the file should NOT be revealed to the datastore!*/
func (userdata *User) StoreFile(filename string, data []byte) {
	var UserWrapper Wrapper
	var ciphertext []byte
	//get file list
	v, b := userlib.DatastoreGet(userdata.KeyForFileList)
	if !b {
		userlib.DebugMsg("not present")
	}

	//FileList contain filename:fileStructure map
	var f FileList
	json.Unmarshal(v, &UserWrapper)
	json.Unmarshal(UserWrapper.EncryptedData, &ciphertext)
	ciphertext = decryptData(ciphertext, userdata.SymmetricKeyForFileList)
	json.Unmarshal(ciphertext[userlib.BlockSize:], &f)

	var fs FileStructure
	fs, exist := f.Files[filename]
	var s SegmentStructure
	//file contain segmentStructureList
	var file File

	if exist == true {
		s1, exists := userlib.DatastoreGet(fs.Key)
		if !exists {
			delete(f.Files, filename)
			userdata.StoreFile(filename, data)
			return
		}
		json.Unmarshal(s1, &UserWrapper)
		//calculate and check HMAC
		maca := calculateHMAC(fs.SymmetricKey, UserWrapper.EncryptedData)
		if !userlib.Equal(maca, UserWrapper.Digest) {
			delete(f.Files, filename)
			userlib.DatastoreDelete(fs.Key)
			userdata.StoreFile(filename, data)
			return
		}
		//decrypting file
		json.Unmarshal(UserWrapper.EncryptedData, &ciphertext)

		ciphertext = decryptData(ciphertext, fs.SymmetricKey)
		json.Unmarshal(ciphertext[userlib.BlockSize:], &file)
		//first elements will be s
		s = file.Segments[0]
		//clear all the segments
		file.Segments = file.Segments[:0]
		userlib.DatastoreDelete(s.SegmentKey)
		//now i can create a new segment and update its hmac to new hmac

	} else {
		//consider this as a new file

		fs.Key = hex.EncodeToString(userlib.RandomBytes(32))

		arr := userlib.RandomBytes(32)
		fs.SymmetricKey = make([]byte, len(arr))
		copy(fs.SymmetricKey, arr)

		fs.Owner = true
		//add this filestructure to map
		f.Files[filename] = fs

		//FileStructure contains Key to a file

		s.SegmentKey = hex.EncodeToString(userlib.RandomBytes(32))
		//
		arr = userlib.RandomBytes(32)
		s.SymmetricKeyforSegment = make([]byte, len(arr))
		copy(s.SymmetricKeyforSegment, arr)

	}

	//this is where actual data is stored
	var frag FileSegment
	frag.Data = data
	d, _ := json.Marshal(frag)
	d = encryptData(d, s.SymmetricKeyforSegment)
	d, _ = json.Marshal(d)
	var segWrapper Wrapper
	segWrapper.EncryptedData = d
	//add hmac of segment to segmentstructure
	segWrapper.Digest = calculateHMAC(s.SymmetricKeyforSegment, d)
	d, _ = json.Marshal(segWrapper)
	userlib.DatastoreSet(s.SegmentKey, d)

	file.Segments = append(file.Segments, s)

	//encrypt file and then wrap it
	data, _ = json.Marshal(file)
	data = encryptData(data, fs.SymmetricKey)
	data, _ = json.Marshal(data)
	var fileWrapper Wrapper
	fileWrapper.EncryptedData = data
	fileWrapper.Digest = calculateHMAC(fs.SymmetricKey, data)
	data, _ = json.Marshal(fileWrapper)
	userlib.DatastoreSet(fs.Key, data)

	data, _ = json.Marshal(f)
	data = encryptData(data, userdata.SymmetricKeyForFileList)
	data, _ = json.Marshal(data)
	var fileListWrapper Wrapper
	fileListWrapper.EncryptedData = data
	fileListWrapper.Digest = calculateHMAC(userdata.SymmetricKeyForFileList, data)
	data, _ = json.Marshal(fileListWrapper)
	userlib.DatastoreSet(userdata.KeyForFileList, data)

}

/*This adds on to an existing file.

Append should be efficient, you shouldn't rewrite or reencrypt the
existing file, but only whatever additional information and
metadata you need.*/

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	fileListKey := userdata.KeyForFileList
	s, exists := userlib.DatastoreGet(fileListKey)
	if !exists {
		return errors.New("--file list not found")
	}

	var UserWrapper Wrapper
	json.Unmarshal(s, &UserWrapper)

	//calculate and check HMAC
	maca := calculateHMAC(userdata.SymmetricKeyForFileList, UserWrapper.EncryptedData)
	if !userlib.Equal(maca, UserWrapper.Digest) {
		return errors.New("--FileList is modified - HMAC is not same")
	}

	//decrypting filelist
	var ciphertext []byte
	json.Unmarshal(UserWrapper.EncryptedData, &ciphertext)
	ciphertext = decryptData(ciphertext, userdata.SymmetricKeyForFileList)
	var fileList FileList
	json.Unmarshal(ciphertext[userlib.BlockSize:], &fileList)

	//now getting File
	f, exists := fileList.Files[filename]

	if !exists {
		return errors.New("--File does not exists")
	}
	//now f stores that structure
	s, exists = userlib.DatastoreGet(f.Key)
	if !exists {
		return errors.New("--file not found")
	}

	json.Unmarshal(s, &UserWrapper)

	//calculate and check HMAC
	maca = calculateHMAC(f.SymmetricKey, UserWrapper.EncryptedData)
	if !userlib.Equal(maca, UserWrapper.Digest) {
		return errors.New("--FileStructure is modified - HMAC is not same")
	}

	//decrypting file
	json.Unmarshal(UserWrapper.EncryptedData, &ciphertext)
	ciphertext = decryptData(ciphertext, f.SymmetricKey)
	var file File
	json.Unmarshal(ciphertext[userlib.BlockSize:], &file)

	//here what key to use?
	var s1 SegmentStructure
	//

	s1.SegmentKey = hex.EncodeToString(userlib.RandomBytes(32))
	arr := userlib.RandomBytes(32)
	s1.SymmetricKeyforSegment = make([]byte, len(arr))
	copy(s1.SymmetricKeyforSegment, arr)

	//this is where actual data is stored
	var frag FileSegment
	frag.Data = data
	d, _ := json.Marshal(frag)
	d = encryptData(d, s1.SymmetricKeyforSegment)
	d, _ = json.Marshal(d)
	var segWrapper Wrapper
	segWrapper.EncryptedData = d
	//add hmac of segment to segmentstructure
	segWrapper.Digest = calculateHMAC(s1.SymmetricKeyforSegment, d)
	d, _ = json.Marshal(segWrapper)
	userlib.DatastoreSet(s1.SegmentKey, d)
	//this is the problem
	file.Segments = append(file.Segments, s1)
	//done

	//encrypt file and then wrap it
	data, _ = json.Marshal(file)
	data = encryptData(data, f.SymmetricKey)
	data, _ = json.Marshal(data)
	var fileWrapper Wrapper
	fileWrapper.EncryptedData = data
	fileWrapper.Digest = calculateHMAC(f.SymmetricKey, data)
	data, _ = json.Marshal(fileWrapper)
	userlib.DatastoreSet(f.Key, data)

	return err
}

/* This loads a file from the Datastore.

It should give an error if the file is corrupted in any way.*/
func (userdata *User) LoadFile(filename string) (data []byte, err error) {

	fileListKey := userdata.KeyForFileList
	s, exists := userlib.DatastoreGet(fileListKey)
	if !exists {
		return data, errors.New("--file list not found")
	}

	var UserWrapper Wrapper
	json.Unmarshal(s, &UserWrapper)

	//calculate and check HMAC
	maca := calculateHMAC(userdata.SymmetricKeyForFileList, UserWrapper.EncryptedData)
	if !userlib.Equal(maca, UserWrapper.Digest) {
		return data, errors.New("--FileList is modified - HMAC is not same")
	}

	//decrypting filelist
	var ciphertext []byte
	json.Unmarshal(UserWrapper.EncryptedData, &ciphertext)
	ciphertext = decryptData(ciphertext, userdata.SymmetricKeyForFileList)
	var fileList FileList
	json.Unmarshal(ciphertext[userlib.BlockSize:], &fileList)

	//now getting File
	f, exists := fileList.Files[filename]
	if !exists {
		return data, errors.New("--File does not exists")
	}
	//now f stores that structure
	s, exists = userlib.DatastoreGet(f.Key)
	if !exists {
		return data, errors.New("--file not found")
	}

	json.Unmarshal(s, &UserWrapper)

	//calculate and check HMAC
	maca = calculateHMAC(f.SymmetricKey, UserWrapper.EncryptedData)
	if !userlib.Equal(maca, UserWrapper.Digest) {
		return data, errors.New("--FileStructure is modified - HMAC is not same")
	}

	//decrypting file
	json.Unmarshal(UserWrapper.EncryptedData, &ciphertext)

	ciphertext = decryptData(ciphertext, f.SymmetricKey)
	var file File
	json.Unmarshal(ciphertext[userlib.BlockSize:], &file)

	//fetching segments
	for _, segStruct := range file.Segments {
		s, exists = userlib.DatastoreGet(segStruct.SegmentKey)
		if !exists {
			return data, errors.New("segment structure not found")
		}
		json.Unmarshal(s, &UserWrapper)
		//calculate and check HMAC
		maca = calculateHMAC(segStruct.SymmetricKeyforSegment, UserWrapper.EncryptedData)
		if !userlib.Equal(maca, UserWrapper.Digest) {
			return data, errors.New("FileStructure is modified - HMAC is not same")
		}
		//decrypting Segment
		json.Unmarshal(UserWrapper.EncryptedData, &ciphertext)

		ciphertext = decryptData(ciphertext, segStruct.SymmetricKeyforSegment)
		var fs FileSegment
		json.Unmarshal(ciphertext[userlib.BlockSize:], &fs)
		data = append(data, fs.Data...)
	}
	//userlib.DebugMsg("file data--> %s", string(data))

	return data, err
}

/* You may want to define what you actually want to pass as a
sharingRecord to serialized/deserialize in the data store.*/
type sharingRecord struct {
	SymmetricKey []byte
	FileKey      []byte //string
}

type sharingKeyWrapper struct {
	Key  []byte
	Sign []byte
}

/* This creates a sharing record, which is a key pointing to something
 in the datastore to share with the recipient.

 This enables the recipient to access the encrypted file as well
 for reading/appending.

Note that neither the recipient NOR the datastore should gain any
information about what the sender calls the file.  Only the
recipient can access the sharing record, and only the recipient
 should be able to know the sender.*/

func (userdata *User) ShareFile(filename string, recipient string) (
	msgid string, err error) {

	//get the file first
	fileListKey := userdata.KeyForFileList
	s, exists := userlib.DatastoreGet(fileListKey)
	if !exists {
		return "", errors.New("--file list not found")
	}

	var UserWrapper Wrapper
	json.Unmarshal(s, &UserWrapper)

	//calculate and check HMAC
	maca := calculateHMAC(userdata.SymmetricKeyForFileList, UserWrapper.EncryptedData)
	if !userlib.Equal(maca, UserWrapper.Digest) {
		return "", errors.New("--FileList is modified - HMAC is not same")
	}

	//decrypting filelist
	var ciphertext []byte
	json.Unmarshal(UserWrapper.EncryptedData, &ciphertext)
	ciphertext = decryptData(ciphertext, userdata.SymmetricKeyForFileList)
	var fileList FileList
	json.Unmarshal(ciphertext[userlib.BlockSize:], &fileList)

	//now getting File
	f, exists := fileList.Files[filename]
	if !exists {
		return "", errors.New("--File does not exists")
	}

	//this record contains info of the file to share
	var record sharingRecord
	val, _ := userlib.KeystoreGet(recipient)
	record.SymmetricKey, _ = userlib.RSAEncrypt(&val, f.SymmetricKey, nil)
	s, _ = hex.DecodeString(f.Key)
	record.FileKey, _ = userlib.RSAEncrypt(&val, s, nil)
	//encrypt the record with receipents RSA key
	d, _ := json.Marshal(record)
	if err != nil {
		//handle error here
	}
	k := hex.EncodeToString(userlib.RandomBytes(32))
	userlib.DatastoreSet(k, d)

	//this is for key
	var wrap sharingKeyWrapper
	wrap.Key, err = hex.DecodeString(k)
	wrap.Key, err = userlib.RSAEncrypt(&val, wrap.Key, nil)
	wrap.Sign, err = userlib.RSASign(&userdata.Key, wrap.Key)
	if err != nil {
		//handl error here
	}
	d, _ = json.Marshal(wrap)
	d1 := hex.EncodeToString(d)
	return d1, err
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	msgid string) error {
	//get the sharing message
	msg, err := hex.DecodeString(msgid)
	if err != nil {
		//handle error here
	}
	var wrap sharingKeyWrapper
	json.Unmarshal(msg, &wrap)

	//get senders public key
	senderPubKey, _ := userlib.KeystoreGet(sender)
	// sender, err = userlib.RSADecrypt(&senderPubKey, msg, nil)

	//verify using senders public key
	//k, _ := hex.DecodeString(wrap.Key)
	err = userlib.RSAVerify(&senderPubKey, wrap.Key, wrap.Sign)
	if err != nil {
		return errors.New("RSAVerify failed")
	}

	wrap.Key, err = userlib.RSADecrypt(&userdata.Key, wrap.Key, nil)
	if err != nil {
		return errors.New("empty rsa key")

	}
	key := hex.EncodeToString(wrap.Key)

	val, exists := userlib.DatastoreGet(key)
	if !exists {
		//do something
		return errors.New("key not found")
	}

	//sharing record
	var record sharingRecord
	json.Unmarshal(val, &record)
	record.FileKey, err = userlib.RSADecrypt(&userdata.Key, record.FileKey, nil)
	record.SymmetricKey, err = userlib.RSADecrypt(&userdata.Key, record.SymmetricKey, nil)

	//add this sharing record to my file structure
	var UserWrapper Wrapper
	var ciphertext []byte
	//get file list
	v, b := userlib.DatastoreGet(userdata.KeyForFileList)
	if !b {
		userlib.DebugMsg("not present")
	}

	//FileList contain filename:fileStructure map
	var f FileList
	json.Unmarshal(v, &UserWrapper)
	json.Unmarshal(UserWrapper.EncryptedData, &ciphertext)
	ciphertext = decryptData(ciphertext, userdata.SymmetricKeyForFileList)
	json.Unmarshal(ciphertext[userlib.BlockSize:], &f)

	var fs FileStructure
	fs.Owner = false
	fs.Key = hex.EncodeToString(record.FileKey)
	fs.SymmetricKey = record.SymmetricKey

	//add this filestructure to map
	f.Files[filename] = fs

	data, _ := json.Marshal(f)
	data = encryptData(data, userdata.SymmetricKeyForFileList)
	data, _ = json.Marshal(data)
	var fileListWrapper Wrapper
	fileListWrapper.EncryptedData = data
	fileListWrapper.Digest = calculateHMAC(userdata.SymmetricKeyForFileList, data)
	data, _ = json.Marshal(fileListWrapper)
	userlib.DatastoreSet(userdata.KeyForFileList, data)

	return nil
}

// Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {

	fileListKey := userdata.KeyForFileList
	s, exists := userlib.DatastoreGet(fileListKey)
	if !exists {
		return errors.New("--file list not found")
	}

	var UserWrapper Wrapper
	json.Unmarshal(s, &UserWrapper)

	//calculate and check HMAC
	maca := calculateHMAC(userdata.SymmetricKeyForFileList, UserWrapper.EncryptedData)
	if !userlib.Equal(maca, UserWrapper.Digest) {
		return errors.New("--FileList is modified - HMAC is not same")
	}

	//decrypting filelist
	var ciphertext []byte
	json.Unmarshal(UserWrapper.EncryptedData, &ciphertext)
	ciphertext = decryptData(ciphertext, userdata.SymmetricKeyForFileList)
	var fileList FileList
	json.Unmarshal(ciphertext[userlib.BlockSize:], &fileList)

	//now getting File
	f, exists := fileList.Files[filename]
	if !exists {
		return errors.New("--File does not exists")
	}

	//only owner can revoke
	if !f.Owner {
		return errors.New("Invalid Operation")
	}
	//

	oldSymmKey := f.SymmetricKey
	//
	arr := userlib.RandomBytes(32)
	f.SymmetricKey = make([]byte, len(arr))
	copy(f.SymmetricKey, arr)

	fileList.Files[filename] = f

	//
	var file File
	s1, exists := userlib.DatastoreGet(f.Key)
	if !exists {
		return errors.New("not exist")
	}
	json.Unmarshal(s1, &UserWrapper)
	//calculate and check HMAC
	maca = calculateHMAC(oldSymmKey, UserWrapper.EncryptedData)
	if !userlib.Equal(maca, UserWrapper.Digest) {
		return errors.New("File corrupted")
	}

	//decrypting file
	json.Unmarshal(UserWrapper.EncryptedData, &ciphertext)
	ciphertext = decryptData(ciphertext, oldSymmKey)
	json.Unmarshal(ciphertext[userlib.BlockSize:], &file)

	data, _ := json.Marshal(file)
	data = encryptData(data, f.SymmetricKey)
	data, _ = json.Marshal(data)
	var fileWrapper Wrapper
	fileWrapper.EncryptedData = data
	fileWrapper.Digest = calculateHMAC(f.SymmetricKey, data)
	data, _ = json.Marshal(fileWrapper)
	userlib.DatastoreSet(f.Key, data)
	//

	data, _ = json.Marshal(fileList)
	data = encryptData(data, userdata.SymmetricKeyForFileList)
	data, _ = json.Marshal(data)
	var fileListWrapper Wrapper
	fileListWrapper.EncryptedData = data
	fileListWrapper.Digest = calculateHMAC(userdata.SymmetricKeyForFileList, data)
	data, _ = json.Marshal(fileListWrapper)
	userlib.DatastoreSet(userdata.KeyForFileList, data)

	return
}
