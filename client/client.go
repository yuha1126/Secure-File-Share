package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username    string
	password    string
	Salt1       []byte
	Salt2       []byte
	StorageUUID uuid.UUID
}

type Storage struct {
	Username    string
	Dictionary  map[string]Tuple
	StorageAuth []byte
	Pkey        userlib.PKEDecKey
}

type File struct {
	ContentUUID uuid.UUID
	Verifier    []byte
	SharedDict  map[string][]string
	InvDict     map[string][]uuid.UUID
	Owner       []byte
}

type Content struct {
	Data     []byte
	PrevUUID uuid.UUID
}

type Invitation struct {
	FileUUID uuid.UUID
	Key      []byte
	Verifier []byte
}

type Tuple struct {
	Key  []byte
	UUID uuid.UUID
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	if username == "" { // may have to change this since username can be any string with 1 or more characters
		return nil, errors.New("Username cannot be empty.")
	}
	tempuser := userlib.Argon2Key([]byte(username), []byte(username), 16) // this part is needed so that username is converted to 16bytes
	userUUID, err := uuid.FromBytes(tempuser)
	if err != nil {
		return nil, err
	}
	_, ok := userlib.DatastoreGet(userUUID)
	if ok {
		return nil, errors.New("Username is already taken.")
	}
	userdata.Username = username
	userdata.password = password
	salt1 := userlib.Hash(userlib.RandomBytes(64))
	salt2 := userlib.Hash(userlib.RandomBytes(64))
	userdata.Salt1 = salt1
	userdata.Salt2 = salt2

	pubEncKey, pubDecKey, err := userlib.PKEKeyGen() // create publickey set for user
	if err != nil {
		return nil, err
	}
	userlib.KeystoreSet(username, pubEncKey)

	var storagedata Storage
	storagedata.Username = username
	storageKey := userlib.Argon2Key([]byte(password), salt2, 16)
	storagedata.StorageAuth = userlib.Hash(userlib.Argon2Key([]byte(password), salt1, 16)) // to make sure storage isn't altered in some way; may not need but as precaution
	storagedata.Pkey = pubDecKey
	dictionary := make(map[string]Tuple) // dictionary used to map files this user has access to
	storagedata.Dictionary = dictionary
	storagebyte, err := json.Marshal(storagedata) // need to convert to bytes to symenc it
	if err != nil {
		return nil, err
	}

	iv := userlib.RandomBytes(16)
	storageEnc := userlib.SymEnc(storageKey, iv, storagebyte) // turns storage byte into SymEncrypted storage data
	storageUUID := uuid.New()
	userdata.StorageUUID = storageUUID

	userlib.DatastoreSet(storageUUID, storageEnc) // send the storage to datastore

	userbyte, err := json.Marshal(userdata)
	if err != nil {
		return nil, err
	}
	userlib.DatastoreSet(userUUID, userbyte)

	return &userdata, err
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	tempuser := userlib.Argon2Key([]byte(username), []byte(username), 16)
	userUUID, err := uuid.FromBytes(tempuser)
	userbyte, ok := userlib.DatastoreGet(userUUID)
	if !ok {
		return nil, errors.New("User with username not found.")
	}
	err = json.Unmarshal(userbyte, &userdata)
	if err != nil {
		return nil, err
	}
	// now authenticate & validate user
	storageByteEnc, ok := userlib.DatastoreGet(userdata.StorageUUID)
	if !ok {
		return nil, errors.New("Malicious action detected while trying to get user. 1") // checking if storage uuid is not deleted
	}
	storageKey := userlib.Argon2Key([]byte(password), userdata.Salt2, 16)
	storageByte := userlib.SymDec(storageKey, storageByteEnc) //gets the storage of the user

	var storage Storage
	err = json.Unmarshal(storageByte, &storage)
	if err != nil {
		return nil, errors.New("Malicious action detected while trying to get user. 2") // checks if salt2 and storage has been attacked
	}
	verify := userlib.Hash(userlib.Argon2Key([]byte(password), userdata.Salt1, 16))
	if !userlib.HMACEqual(verify, storage.StorageAuth) {
		return nil, errors.New("Incorrect password or malicious attack detected.")
	}

	// store password of user again
	userdata.password = password
	return &userdata, err
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	var filedata File
	contentUUID := uuid.New()
	verifierByte := userlib.RandomBytes(20)
	//prevUUID := uuid.New()

	var contentdata Content
	contentdata.Data = content
	contentdata.PrevUUID = uuid.Nil
	contentBytes, err := json.Marshal(contentdata) //turning contentdata into bytes
	if err != nil {
		return err
	}
	symKey := userlib.RandomBytes(16)
	iv := userlib.RandomBytes(16)
	contentEnc := userlib.SymEnc(symKey, iv, contentBytes) //encrypt the content
	userlib.DatastoreSet(contentUUID, contentEnc)          // send the content to datastore

	filedata.ContentUUID = contentUUID
	filedata.Verifier = verifierByte
	sharedDictionary := make(map[string][]string)
	filedata.SharedDict = sharedDictionary
	invDictionary := make(map[string][]uuid.UUID)
	filedata.InvDict = invDictionary

	//Get the file creator username
	storageByteEnc, ok := userlib.DatastoreGet(userdata.StorageUUID)
	if !ok {
		return errors.New("Malicious action detected while trying to store file. 1") // checking if storage uuid is not deleted
	}
	storageKey := userlib.Argon2Key([]byte(userdata.password), userdata.Salt2, 16)
	storageByte := userlib.SymDec(storageKey, storageByteEnc)
	var storage Storage
	err = json.Unmarshal(storageByte, &storage)
	if err != nil {
		return errors.New("Malicious action detected while trying to store file. 2") // checking to make sure User / Storage wasn't altered
	}
	filedata.Owner = userlib.Hash(userlib.Argon2Key([]byte(userdata.password), userdata.Salt1, 16))
	// has to use storage username because User.Username is not safe

	//encrypt file, send it to datastore
	fileUUID := uuid.New()
	fileByte, err := json.Marshal(filedata)
	if err != nil {
		return err
	}
	iv = userlib.RandomBytes(16)
	fileByteEnc := userlib.SymEnc(symKey, iv, fileByte) //use the same symkey as before
	userlib.DatastoreSet(fileUUID, fileByteEnc)

	// add file to the user files list
	var fileTuple Tuple
	fileTuple.Key = symKey
	fileTuple.UUID = fileUUID
	storage.Dictionary[filename] = fileTuple

	// update & send storage to datastore
	iv = userlib.RandomBytes(16)
	storageByte, err = json.Marshal(storage)
	if err != nil {
		return err
	}
	storageByteEnc = userlib.SymEnc(storageKey, iv, storageByte) // re encrypt storage
	userlib.DatastoreSet(userdata.StorageUUID, storageByteEnc)

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	// retrieve file information
	storageEncByte, ok := userlib.DatastoreGet(userdata.StorageUUID)
	if !ok {
		return errors.New("Malicious action detected while trying to append file. 0") // checking if storage uuid is not deleted
	}
	storageKey := userlib.Argon2Key([]byte(userdata.password), userdata.Salt2, 16)
	storageByte := userlib.SymDec(storageKey, storageEncByte)
	var storage Storage
	err := json.Unmarshal(storageByte, &storage)
	if err != nil {
		return err // checking to make sure User / Storage wasn't altered
	}
	fileTuple, ok := storage.Dictionary[filename]
	if !ok {
		return errors.New("Given filename does not exist in personal file namespace of caller.")
	}
	fileByteEnc, ok := userlib.DatastoreGet(fileTuple.UUID)
	if !ok {
		return errors.New("Malicious action detected while trying to append file. 2") // if file could not be found in the data store.
	}

	// decrypt file
	fileByte := userlib.SymDec(fileTuple.Key, fileByteEnc)
	var file File
	err = json.Unmarshal(fileByte, &file)
	if err != nil {
		return errors.New("Malicious action detected while trying to append file. 3") // if file struct has been tampered with
	}

	// retrieve content info & create new content
	contentByteEnc, ok := userlib.DatastoreGet(file.ContentUUID)
	if !ok {
		return errors.New("Malicious action detected while trying to append file. 4") // checking if content UUID was obstructed
	}
	prevUUID := uuid.New()
	var newContent Content
	newContent.Data = content
	newContent.PrevUUID = prevUUID // setting the backwards pointer of the new content struct
	newContentByte, err := json.Marshal(newContent)
	if err != nil {
		return err
	}
	iv := userlib.RandomBytes(16)
	newContentByteEnc := userlib.SymEnc(fileTuple.Key, iv, newContentByte) // encrypt the newContents

	// readjust content pointers
	userlib.DatastoreSet(prevUUID, contentByteEnc)
	userlib.DatastoreSet(file.ContentUUID, newContentByteEnc)

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	// retrieve file information
	storageEncByte, ok := userlib.DatastoreGet(userdata.StorageUUID)
	if !ok {
		return nil, errors.New("Malicious action detected while trying to load file. 0") // checking if storage uuid is not deleted
	}
	storageKey := userlib.Argon2Key([]byte(userdata.password), userdata.Salt2, 16)
	storageByte := userlib.SymDec(storageKey, storageEncByte)
	var storage Storage
	err = json.Unmarshal(storageByte, &storage)
	if err != nil {
		return nil, errors.New("Malicious action detected while trying to load file. 1") // checking to make sure User / Storage wasn't altered
	}
	fileTuple, ok := storage.Dictionary[filename]
	if !ok {
		return nil, errors.New("Given filename does not exist in personal file namespace of caller.") // checking whether user has filename
	}

	// Decrypt file and get the content information
	fileByteEnc, ok := userlib.DatastoreGet(fileTuple.UUID)
	fileByte := userlib.SymDec(fileTuple.Key, fileByteEnc)
	var file File
	err = json.Unmarshal(fileByte, &file)
	if err != nil {
		return nil, errors.New("Malicious action detected while trying to load file. 2") // checking to make sure file wasn't messed with
	}
	contentByteEnc, ok := userlib.DatastoreGet(file.ContentUUID)
	if !ok {
		return nil, errors.New("Malicious action detected while trying to load file. 3") // checking if content UUID was obstructed
	}
	contentByte := userlib.SymDec(fileTuple.Key, contentByteEnc)
	var fcontent Content
	err = json.Unmarshal(contentByte, &fcontent)
	if err != nil {
		return nil, errors.New("Malicious action detected while trying to load file. 4")
	}
	// start to reconstruct data by traversing through reverse linked list
	retString := string(fcontent.Data)
	for fcontent.PrevUUID != uuid.Nil {
		// return nil, nil
		// traverse one node back
		contentByteEnc, ok = userlib.DatastoreGet(fcontent.PrevUUID)
		if !ok {
			return nil, errors.New("Malicious action detected while trying to load file. 5") // if the prevuuid has been destroyed
		}
		contentByte = userlib.SymDec(fileTuple.Key, contentByteEnc)
		err = json.Unmarshal(contentByte, &fcontent)
		if err != nil {
			return nil, errors.New("Malicious action detected while trying to load file. 6") // if the prev node has been changed or altered in some way
		}
		contentData := string(fcontent.Data)
		retString = contentData + retString

	}

	return []byte(retString), err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {

	// check to make sure the recipient exists
	tempRecipient := userlib.Argon2Key([]byte(recipientUsername), []byte(recipientUsername), 16)
	recipientUUID, err := uuid.FromBytes(tempRecipient)
	if err != nil {
		return uuid.Nil, err
	}
	_, ok := userlib.DatastoreGet(recipientUUID)
	if !ok {
		return uuid.Nil, errors.New("Recipient username does not exist.")
	}

	// retrieve storage data
	storageEncByte, ok := userlib.DatastoreGet(userdata.StorageUUID)
	if !ok {
		return uuid.Nil, errors.New("Malicious action detected while trying to create invitation. 0")
	}
	storageKey := userlib.Argon2Key([]byte(userdata.password), userdata.Salt2, 16)
	storageByte := userlib.SymDec(storageKey, storageEncByte)
	var storage Storage
	err = json.Unmarshal(storageByte, &storage)
	if err != nil {
		return uuid.Nil, errors.New("Malicious action detected while trying to create invitation. 1")
	}

	// retrieve file info
	fileTuple, ok := storage.Dictionary[filename]
	if !ok {
		return uuid.Nil, errors.New("Given filename does not exist in personal file namespace of caller.") // checking whether user has filename
	}
	fileByteEnc, ok := userlib.DatastoreGet(fileTuple.UUID)
	if !ok {
		return uuid.Nil, errors.New("Malicious action detected while trying to create invitation. 2")
	}
	fileByte := userlib.SymDec(fileTuple.Key, fileByteEnc)
	var file File
	err = json.Unmarshal(fileByte, &file)
	if err != nil {
		return uuid.Nil, errors.New("Malicious action detected while trying to create invitation. 3")
	}

	// create invitation struct
	invUUID := uuid.New()
	var invitation Invitation
	invitation.Key = fileTuple.Key
	invitation.FileUUID = fileTuple.UUID
	invitation.Verifier = file.Verifier

	// encrypt invitation and send to datastore
	invitationByte, err := json.Marshal(invitation)
	if err != nil {
		return uuid.Nil, err
	}
	recipientPubKey, ok := userlib.KeystoreGet(recipientUsername)
	if !ok {
		return uuid.Nil, errors.New("Given recipient username not found.")
	}
	invitationByteEnc, err := userlib.PKEEnc(recipientPubKey, invitationByte)
	if err != nil {
		return uuid.Nil, err
	}
	userlib.DatastoreSet(invUUID, invitationByteEnc)

	// add invited user to the filedictionary
	file.SharedDict[userdata.Username] = make([]string, 0)
	file.SharedDict[userdata.Username] = append(file.SharedDict[userdata.Username], recipientUsername)
	file.InvDict[userdata.Username] = make([]uuid.UUID, 0)
	file.InvDict[userdata.Username] = append(file.InvDict[userdata.Username], recipientUUID)

	// send file to datastore
	fileByte, err = json.Marshal(file)
	if err != nil {
		return uuid.Nil, err
	}
	iv := userlib.RandomBytes(16)
	fileByteEnc = userlib.SymEnc(fileTuple.Key, iv, fileByte) //use the same symkey as before
	userlib.DatastoreSet(fileTuple.UUID, fileByteEnc)

	return invUUID, err
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	// retrieve storage data
	storageByteEnc, ok := userlib.DatastoreGet(userdata.StorageUUID)
	if !ok {
		return errors.New("Malicious action detected while trying to accept invitation. 0")
	}
	storageKey := userlib.Argon2Key([]byte(userdata.password), userdata.Salt2, 16)
	storageByte := userlib.SymDec(storageKey, storageByteEnc)
	var storage Storage
	err := json.Unmarshal(storageByte, &storage)
	if err != nil {
		return errors.New("Malicious action detected while trying to accept invitation. 1")
	}

	// checking if filename already exists
	_, ok = storage.Dictionary[filename]
	if ok {
		return errors.New("Filename already exists in user's personal file namespace.")
	}

	// decrypt invitation
	invitationByteEnc, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("Something about the invitation ptr is wrong.")
	}
	invitationByte, err := userlib.PKEDec(storage.Pkey, invitationByteEnc)
	if err != nil {
		return errors.New("Malicious action detected while trying to accept invitation. 2")
	}
	var invitation Invitation
	err = json.Unmarshal(invitationByte, &invitation)
	if err != nil {
		return err
	}

	// check if sender is valid
	fileByteEnc, ok := userlib.DatastoreGet(invitation.FileUUID)
	if !ok {
		return errors.New("Malicious action detected while trying to accept invitation. 3")
	}
	fileByte := userlib.SymDec(invitation.Key, fileByteEnc)
	var file File
	err = json.Unmarshal(fileByte, &file)
	if err != nil {
		return errors.New("Malicious action detected while trying to accept invitation. 4")
	}
	if !userlib.HMACEqual(invitation.Verifier, file.Verifier) {
		return errors.New("Failed to authenticate sender.")
	}

	// add user to file
	var tuple Tuple
	tuple.Key = invitation.Key
	tuple.UUID = invitation.FileUUID
	storage.Dictionary[filename] = tuple

	// send updated file to datastore
	iv := userlib.RandomBytes(16)
	storageByte, err = json.Marshal(storage)
	if err != nil {
		return err
	}
	storageByteEnc = userlib.SymEnc(storageKey, iv, storageByte)
	userlib.DatastoreSet(userdata.StorageUUID, storageByteEnc)

	return err
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	// retrieve storage data
	storageByteEnc, ok := userlib.DatastoreGet(userdata.StorageUUID)
	if !ok {
		return errors.New("Malicious action detected while trying to revoke access. 0")
	}
	storageKey := userlib.Argon2Key([]byte(userdata.password), userdata.Salt2, 16)
	storageByte := userlib.SymDec(storageKey, storageByteEnc)
	var storage Storage
	err := json.Unmarshal(storageByte, &storage)
	if err != nil {
		return errors.New("Malicious action detected while trying to revoke access. 1")
	}

	// retrieving file info
	fileTuple, ok := storage.Dictionary[filename]
	if !ok {
		return errors.New("Given filename does not exist in personal file namespace of caller.") // checking whether user has filename
	}
	fileByteEnc, ok := userlib.DatastoreGet(fileTuple.UUID)
	if !ok {
		return errors.New("Malicious action detected while trying to revoke access. 2")
	}
	fileByte := userlib.SymDec(fileTuple.Key, fileByteEnc)
	var file File
	err = json.Unmarshal(fileByte, &file)
	if err != nil {
		return errors.New("Malicious action detected while trying to revoke access. 3")
	}

	// checking to make sure user has revoke access
	ownerAuth := userlib.Hash(userlib.Argon2Key([]byte(userdata.password), userdata.Salt1, 16))
	if !userlib.HMACEqual(ownerAuth, file.Owner) {
		return errors.New("User does not have revoke access to this file.")
	}

	// checking to make sure file is shared with the recipient
	_, ok = file.InvDict[recipientUsername]
	if !ok {
		return errors.New("File currently not shared by recipient user.")
	}
	_, ok = file.SharedDict[recipientUsername] // this should have value as a list of string
	if !ok {
		return errors.New("File currently not shared by recipient user.")
	}

	return err
}
