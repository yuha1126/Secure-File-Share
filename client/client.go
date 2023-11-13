package client

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	"errors"

	_ "strconv"
)

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
	InvDict     map[string]uuid.UUID
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

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	if username == "" {
		return nil, errors.New("username cannot be empty")
	}
	tempuser := userlib.Argon2Key([]byte(username), []byte(username), 16) // this part is needed so that username is converted to 16bytes
	userUUID, err := uuid.FromBytes(tempuser)
	if err != nil {
		return nil, err
	}
	_, ok := userlib.DatastoreGet(userUUID)
	if ok {
		return nil, errors.New("username is already taken")
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
	if err != nil {
		return nil, errors.New("malicious action detected while trying to get user. 0")
	}
	userbyte, ok := userlib.DatastoreGet(userUUID)
	if !ok {
		return nil, errors.New("user with username not found")
	}
	err = json.Unmarshal(userbyte, &userdata)
	if err != nil {
		return nil, err
	}
	// now authenticate & validate user
	storageByteEnc, ok := userlib.DatastoreGet(userdata.StorageUUID)
	if !ok {
		return nil, errors.New("malicious action detected while trying to get user. 1") // checking if storage uuid is not deleted
	}
	storageKey := userlib.Argon2Key([]byte(password), userdata.Salt2, 16)
	storageByte := userlib.SymDec(storageKey, storageByteEnc) //gets the storage of the user

	var storage Storage
	err = json.Unmarshal(storageByte, &storage)
	if err != nil {
		return nil, errors.New("malicious action detected while trying to get user. 2") // checks if salt2 and storage has been attacked
	}
	verify := userlib.Hash(userlib.Argon2Key([]byte(password), userdata.Salt1, 16))
	if !userlib.HMACEqual(verify, storage.StorageAuth) {
		return nil, errors.New("incorrect password or malicious attack detected")
	}

	// store password of user again
	userdata.password = password
	return &userdata, err
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	var filedata File
	contentUUID := uuid.New()
	verifierByte := userlib.RandomBytes(20)

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
	invDictionary := make(map[string]uuid.UUID)
	filedata.InvDict = invDictionary

	//Get the file creator username
	storageByteEnc, ok := userlib.DatastoreGet(userdata.StorageUUID)
	if !ok {
		return errors.New("malicious action detected while trying to store file. 1") // checking if storage uuid is not deleted
	}
	storageKey := userlib.Argon2Key([]byte(userdata.password), userdata.Salt2, 16)
	storageByte := userlib.SymDec(storageKey, storageByteEnc)
	var storage Storage
	err = json.Unmarshal(storageByte, &storage)
	if err != nil {
		return errors.New("malicious action detected while trying to store file. 2") // checking to make sure User / Storage wasn't altered
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
		return errors.New("malicious action detected while trying to append file. 0") // checking if storage uuid is not deleted
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
		return errors.New("given filename does not exist in personal file namespace of caller")
	}

	// have to check whether the file was from an invite or it's the owners
	fileByteEnc, ok := userlib.DatastoreGet(fileTuple.UUID)
	if !ok {
		return errors.New("either malicious action detected or user no longer has access to file")
	}

	fileByte := userlib.SymDec(fileTuple.Key, fileByteEnc)
	var file File
	var invitation Invitation
	var contentByteEnc []byte
	err = json.Unmarshal(fileByte, &file)
	if err != nil { // checking if the file trying to load is from an invitation or not
		inviteByte, err := userlib.PKEDec(storage.Pkey, fileByteEnc)
		if err != nil {
			return errors.New("malicious action detected while trying to append file. 2")
		}
		err = json.Unmarshal(inviteByte, &invitation)
		if err != nil {
			return errors.New("malicious action detected while trying to append file. 2.1")
		}
		fileByteEnc, ok = userlib.DatastoreGet(invitation.FileUUID)
		if !ok {
			return errors.New("malicious action detected while trying to append file. 2.2") // checking if content UUID was obstructed
		}
		fileByte = userlib.SymDec(fileTuple.Key, fileByteEnc)
		err = json.Unmarshal(fileByte, &file)
		if err != nil {
			return errors.New("malicious action detected while trying to append file. 2.3")
		}
		contentByteEnc, ok = userlib.DatastoreGet(file.ContentUUID)
		if !ok {
			return errors.New("malicious action detected while trying to append file. 2.4") // checking if content UUID was obstructed
		}
	} else {
		contentByteEnc, ok = userlib.DatastoreGet(file.ContentUUID)
		if !ok {
			return errors.New("malicious action detected while trying to append file. 3") // checking if content UUID was obstructed
		}
	}

	// retrieve content info & create new content
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
		return nil, errors.New("malicious action detected while trying to load file. 0") // checking if storage uuid is not deleted
	}
	storageKey := userlib.Argon2Key([]byte(userdata.password), userdata.Salt2, 16)
	storageByte := userlib.SymDec(storageKey, storageEncByte)
	var storage Storage
	err = json.Unmarshal(storageByte, &storage)
	if err != nil {
		return nil, errors.New("malicious action detected while trying to load file. 1") // checking to make sure User / Storage wasn't altered
	}
	fileTuple, ok := storage.Dictionary[filename]
	if !ok {
		return nil, errors.New("given filename does not exist in personal file namespace of caller") // checking whether user has filename
	}

	// Decrypt file and get the content information
	fileByteEnc, ok := userlib.DatastoreGet(fileTuple.UUID)
	if !ok {
		return nil, errors.New("either malicious action detected or user no longer has access to file")
	}

	fileByte := userlib.SymDec(fileTuple.Key, fileByteEnc)
	var file File
	var invitation Invitation
	var contentByteEnc []byte
	err = json.Unmarshal(fileByte, &file)
	if err != nil { // checking if the file trying to load is from an invitation or not
		inviteByte, err := userlib.PKEDec(storage.Pkey, fileByteEnc)
		if err != nil {
			return nil, errors.New("malicious action detected while trying to load file. 2")
		}
		err = json.Unmarshal(inviteByte, &invitation)
		if err != nil {
			return nil, errors.New("malicious action detected while trying to load file. 2.1")
		}
		fileByteEnc, ok = userlib.DatastoreGet(invitation.FileUUID)
		if !ok {
			return nil, errors.New("malicious action detected while trying to load file. 2.2") // checking if content UUID was obstructed
		}
		fileByte = userlib.SymDec(fileTuple.Key, fileByteEnc)
		err = json.Unmarshal(fileByte, &file)
		if err != nil {
			return nil, errors.New("malicious action detected while trying to load file. 2.3")
		}
		contentByteEnc, ok = userlib.DatastoreGet(file.ContentUUID)
		if !ok {
			return nil, errors.New("malicious action detected while trying to load file. 2.4") // checking if content UUID was obstructed
		}
	} else {
		contentByteEnc, ok = userlib.DatastoreGet(file.ContentUUID)
		if !ok {
			return nil, errors.New("malicious action detected while trying to load file. 3") // checking if content UUID was obstructed
		}
	}

	contentByte := userlib.SymDec(fileTuple.Key, contentByteEnc)
	var fcontent Content
	err = json.Unmarshal(contentByte, &fcontent)
	if err != nil {
		return nil, errors.New("malicious action detected while trying to load file. 4")
	}

	// start to reconstruct data by traversing through reverse linked list
	retString := string(fcontent.Data)
	for fcontent.PrevUUID != uuid.Nil {
		// return nil, nil
		// traverse one node back
		contentByteEnc, ok = userlib.DatastoreGet(fcontent.PrevUUID)
		if !ok {
			return nil, errors.New("malicious action detected while trying to load file. 5") // if the prevuuid has been destroyed
		}
		contentByte = userlib.SymDec(fileTuple.Key, contentByteEnc)
		err = json.Unmarshal(contentByte, &fcontent)
		if err != nil {
			return nil, errors.New("malicious action detected while trying to load file. 6") // if the prev node has been changed or altered in some way
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
		return uuid.Nil, errors.New("recipient username does not exist")
	}

	// retrieve storage data
	storageEncByte, ok := userlib.DatastoreGet(userdata.StorageUUID)
	if !ok {
		return uuid.Nil, errors.New("malicious action detected while trying to create invitation. 0")
	}
	storageKey := userlib.Argon2Key([]byte(userdata.password), userdata.Salt2, 16)
	storageByte := userlib.SymDec(storageKey, storageEncByte)
	var storage Storage
	err = json.Unmarshal(storageByte, &storage)
	if err != nil {
		return uuid.Nil, errors.New("malicious action detected while trying to create invitation. 1")
	}

	// retrieve file info
	fileTuple, ok := storage.Dictionary[filename] // uuid of this tuple either points to an invitation or a file
	if !ok {
		return uuid.Nil, errors.New("given filename does not exist in personal file namespace of caller") // checking whether user has filename
	}

	fileByteEnc, ok := userlib.DatastoreGet(fileTuple.UUID)
	if !ok {
		return uuid.Nil, errors.New("malicious action detected while trying to create invitation. 1.1")
	}
	fileByte := userlib.SymDec(fileTuple.Key, fileByteEnc)
	var file File
	var tempinvitation Invitation
	isOwner := true
	err = json.Unmarshal(fileByte, &file)
	if err != nil { // checking if the file trying to load is from an invitation or not
		isOwner = false
		inviteByte, err := userlib.PKEDec(storage.Pkey, fileByteEnc)
		if err != nil {
			return uuid.Nil, errors.New("malicious action detected while trying to create invitation. 2")
		}
		err = json.Unmarshal(inviteByte, &tempinvitation)
		if err != nil {
			return uuid.Nil, errors.New("malicious action detected while trying to create invitation. 2.1")
		}
		fileByteEnc, ok = userlib.DatastoreGet(tempinvitation.FileUUID)
		if !ok {
			return uuid.Nil, errors.New("malicious action detected while trying to create invitation. 2.2") // checking if content UUID was obstructed
		}
		fileByte = userlib.SymDec(fileTuple.Key, fileByteEnc)
		err = json.Unmarshal(fileByte, &file)
		if err != nil {
			return uuid.Nil, errors.New("malicious action detected while trying to create invitation. 2.3")
		}
	}

	// create invitation struct
	invUUID := uuid.New()
	var invitation Invitation
	invitation.Key = fileTuple.Key
	if isOwner {
		invitation.FileUUID = fileTuple.UUID
	} else {
		invitation.FileUUID = tempinvitation.FileUUID
	}
	invitation.Verifier = file.Verifier

	// encrypt invitation and send to datastore
	invitationByte, err := json.Marshal(invitation)
	if err != nil {
		return uuid.Nil, err
	}
	recipientPubKey, ok := userlib.KeystoreGet(recipientUsername)
	if !ok {
		return uuid.Nil, errors.New("given recipient username not found")
	}
	invitationByteEnc, err := userlib.PKEEnc(recipientPubKey, invitationByte)
	if err != nil {
		return uuid.Nil, err
	}
	userlib.DatastoreSet(invUUID, invitationByteEnc)

	// add invited user to the filedictionary
	file.SharedDict[userdata.Username] = append(file.SharedDict[userdata.Username], recipientUsername)
	file.InvDict[recipientUsername] = invUUID

	// send file to datastore
	fileByte, err = json.Marshal(file)
	if err != nil {
		return uuid.Nil, err
	}
	iv := userlib.RandomBytes(16)
	fileByteEnc = userlib.SymEnc(fileTuple.Key, iv, fileByte) //use the same symkey as before
	if isOwner {
		userlib.DatastoreSet(fileTuple.UUID, fileByteEnc)
	} else {
		userlib.DatastoreSet(tempinvitation.FileUUID, fileByteEnc)
	}

	return invUUID, err
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	// retrieve storage data
	storageByteEnc, ok := userlib.DatastoreGet(userdata.StorageUUID)
	if !ok {
		return errors.New("malicious action detected while trying to accept invitation. 0")
	}
	storageKey := userlib.Argon2Key([]byte(userdata.password), userdata.Salt2, 16)
	storageByte := userlib.SymDec(storageKey, storageByteEnc)
	var storage Storage
	err := json.Unmarshal(storageByte, &storage)
	if err != nil {
		return errors.New("malicious action detected while trying to accept invitation. 1")
	}

	// checking if filename already exists
	_, ok = storage.Dictionary[filename]
	if ok {
		return errors.New("filename already exists in user's personal file namespace")
	}

	// decrypt invitation
	invitationByteEnc, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("something about the invitation ptr is wrong")
	}
	invitationByte, err := userlib.PKEDec(storage.Pkey, invitationByteEnc)
	if err != nil {
		return errors.New("malicious action detected while trying to accept invitation. 2")
	}
	var invitation Invitation
	err = json.Unmarshal(invitationByte, &invitation)
	if err != nil {
		return err
	}

	// check if sender is valid
	fileByteEnc, ok := userlib.DatastoreGet(invitation.FileUUID)
	if !ok {
		return errors.New("malicious action detected while trying to accept invitation. 3")
	}
	fileByte := userlib.SymDec(invitation.Key, fileByteEnc)
	var file File
	err = json.Unmarshal(fileByte, &file)
	if err != nil {
		return errors.New("malicious action detected while trying to accept invitation. 4")
	}
	if !userlib.HMACEqual(invitation.Verifier, file.Verifier) {
		return errors.New("failed to authenticate sender")
	}

	// checking if the sender has the correct name
	_, ok = file.SharedDict[senderUsername]
	if !ok {
		return errors.New("failed to authenticate sender 2")
	}
	correct := false
	for _, thisUser := range file.SharedDict[senderUsername] {
		if thisUser == userdata.Username {
			correct = true
		}
	}
	if !correct {
		return errors.New("failed to authenticate sender 3")
	}

	// add file to user
	var tuple Tuple
	tuple.Key = invitation.Key
	tuple.UUID = invitationPtr
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
		return errors.New("malicious action detected while trying to revoke access. 0")
	}
	storageKey := userlib.Argon2Key([]byte(userdata.password), userdata.Salt2, 16)
	storageByte := userlib.SymDec(storageKey, storageByteEnc)
	var storage Storage
	err := json.Unmarshal(storageByte, &storage)
	if err != nil {
		return errors.New("malicious action detected while trying to revoke access. 1")
	}

	// retrieving file info
	fileTuple, ok := storage.Dictionary[filename]
	if !ok {
		return errors.New("given filename does not exist in personal file namespace of caller") // checking whether user has filename
	}
	fileByteEnc, ok := userlib.DatastoreGet(fileTuple.UUID)
	if !ok {
		return errors.New("malicious action detected while trying to revoke access. 2")
	}
	fileByte := userlib.SymDec(fileTuple.Key, fileByteEnc)
	var file File
	err = json.Unmarshal(fileByte, &file)
	if err != nil {
		return errors.New("malicious action detected while trying to revoke access or User doesn't have revoking access to this file. 3")
	}

	// checking to make sure user has revoke access
	ownerAuth := userlib.Hash(userlib.Argon2Key([]byte(userdata.password), userdata.Salt1, 16))
	if !userlib.HMACEqual(ownerAuth, file.Owner) {
		return errors.New("user does not have revoke access to this file")
	}

	// checking to make sure file is shared with the recipient
	_, ok = file.InvDict[recipientUsername]
	if !ok {
		return errors.New("file currently not shared by recipient user. 1")
	}
	if !containsVal(file.SharedDict[userdata.Username], recipientUsername) {
		return errors.New("file currently not shared by recipient user. 2")
	}

	// iterate through sharedDict
	idlst := []string{}
	visited := make(map[string]bool)
	dfs(file.SharedDict, recipientUsername, visited, &idlst)

	// iterate through the list of users that need to be revoked and delete them
	for i := 0; i < len(file.SharedDict[userdata.Username]); i++ {
		if file.SharedDict[userdata.Username][i] == recipientUsername {
			file.SharedDict[userdata.Username] = append(file.SharedDict[userdata.Username][:i], file.SharedDict[userdata.Username][i+1:]...)
			break
		}
	}
	for i := 0; i < len(idlst); i++ {
		delete(file.SharedDict, idlst[i])
		if delInv, ok := file.InvDict[idlst[i]]; ok {
			userlib.DatastoreDelete(delInv)
			delete(file.InvDict, idlst[i])
		}
	}

	// create new uuid for file and re encrypt file
	newUUID := uuid.New()
	newVerifier := userlib.RandomBytes(20)
	file.Verifier = newVerifier
	fileByte, err = json.Marshal(file)
	if err != nil {
		return err
	}
	iv := userlib.RandomBytes(16)
	fileByteEnc = userlib.SymEnc(fileTuple.Key, iv, fileByte)
	userlib.DatastoreSet(newUUID, fileByteEnc)
	userlib.DatastoreDelete(fileTuple.UUID) // delete the original file location

	// readjust owner storage
	var newFileTuple Tuple
	newFileTuple.Key = fileTuple.Key
	newFileTuple.UUID = newUUID
	storage.Dictionary[filename] = newFileTuple
	storageByte, err = json.Marshal(storage)
	if err != nil {
		return err
	}
	iv = userlib.RandomBytes(16)
	storageByteEnc = userlib.SymEnc(storageKey, iv, storageByte)
	userlib.DatastoreSet(userdata.StorageUUID, storageByteEnc)

	// retraverse through graph in order to get all nodes that are still left
	newidlst := []string{}
	newvisited := make(map[string]bool)
	dfs(file.SharedDict, userdata.Username, newvisited, &newidlst)

	// iterate through remaining users and give them their invitations back
	for i := 0; i < len(newidlst); i++ {
		if newidlst[i] == userdata.Username { // think about edge case when invitation uuid is changed to point to a different file
			continue
		}
		var newInvitation Invitation
		newInvitation.Key = fileTuple.Key
		newInvitation.FileUUID = newUUID
		newInvitation.Verifier = newVerifier
		// encrypt new invitation
		newInvitationByte, err := json.Marshal(newInvitation)
		if err != nil {
			return err
		}
		userPubKey, ok := userlib.KeystoreGet(newidlst[i])
		if !ok {
			return errors.New("user public key not found in keystore")
		}
		newInvitationByteEnc, err := userlib.PKEEnc(userPubKey, newInvitationByte)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(file.InvDict[newidlst[i]], newInvitationByteEnc)
	}
	return err
}

func containsVal(list []string, value string) bool {
	for _, element := range list {
		if element == value {
			return true
		}
	}
	return false
}

func dfs(tree map[string][]string, start string, visited map[string]bool, result *[]string) { //helper method
	if visited[start] {
		return
	}
	visited[start] = true
	*result = append(*result, start)

	for _, neighbor := range tree[start] {
		dfs(tree, neighbor, visited, result)
	}
}
