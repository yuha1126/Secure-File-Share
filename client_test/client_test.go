package client_test

import (
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

var _ = Describe("Client Tests", func() {

	var alice *client.User
	var bob *client.User
	var charles *client.User
	var doris *client.User
	var eve *client.User
	var frank *client.User
	var grace *client.User
	var horace *client.User
	var ira *client.User

	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	dorisFile := "dorisFile.txt"
	eveFile := "eveFile.txt"
	frankFile := "frankFile.txt"
	graceFile := "graceFile.txt"
	horaceFile := "horaceFile.txt"
	iraFile := "iraFile.txt"

	BeforeEach(func() {
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Authentication Tests", func() {

		Specify("Authentication Test: Testing if usernames are the same.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Reinitializing user Alice.")
			aliceLaptop, err = client.InitUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Authentication Test: Testing password same as username.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", "alice")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", "alice")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice with incorrect password.")
			aliceLaptop, err = client.GetUser("alice", "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Authentication Test: Testing blank username.", func() {
			userlib.DebugMsg("Initializing user ___.")
			alice, err = client.InitUser("", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Authentication Test: Testing blank password.", func() {
			userlib.DebugMsg("Initializing user alice.")
			alice, err = client.InitUser("alice", "")
			Expect(err).To(BeNil())
		})

		Specify("Authentication Test: Testing case sensitivity.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("Alice", "defaultPassword")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user alice.")
			alice, err = client.InitUser("alice", "defaultPassword")
			Expect(err).To(BeNil())
			bob, err = client.GetUser("alice", "DefaultPassword")
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("File Tests", func() {

		Specify("File Test: basic test for storing file.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file data: %s", contentOne)
			_, err := alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentTwo)
			err = alice.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			alice, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("File Test: basic test for appending file.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("File Test: Test to make sure it can't append to missing file.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

	})

	Describe("Share Tests", func() {

		Specify("Share Test: Testing basic file share.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())
			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice creating invite for Bob.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			invite2, err := alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Charles accepting invite from Alice under filename %s.", charlesFile)
			err = charles.AcceptInvitation("alice", invite2, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Revoking stuff 1")
			err = bob.RevokeAccess(bobFile, "eve")
			Expect(err).ToNot(BeNil())
			userlib.DebugMsg("Revoking stuff 2")
			err = alice.RevokeAccess(bobFile, "bob")
			Expect(err).ToNot(BeNil())
			userlib.DebugMsg("Revoking stuff 3")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles creates invitation")
			invite, err = charles.CreateInvitation(charlesFile, "doris")
			Expect(err).To(BeNil())
			err = doris.AcceptInvitation("alice", invite, dorisFile)
			Expect(err).ToNot(BeNil())
			err = doris.AcceptInvitation("charles", invite, dorisFile)
			Expect(err).To(BeNil())

		})

	})

	Describe("Revocation Tests", func() {

		Specify("Revocation Test: Testing basic file share.", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())
			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())
			eve, err = client.InitUser("eve", defaultPassword)
			Expect(err).To(BeNil())
			frank, err = client.InitUser("frank", defaultPassword)
			Expect(err).To(BeNil())
			grace, err = client.InitUser("grace", defaultPassword)
			Expect(err).To(BeNil())
			horace, err = client.InitUser("horace", defaultPassword)
			Expect(err).To(BeNil())
			ira, err = client.InitUser("ira", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))
			userlib.DebugMsg("Bob storing file %s with content: %s", aliceFile, contentTwo)
			bob.StoreFile(aliceFile, []byte(contentTwo))
			userlib.DebugMsg("Charles storing file %s with content: %s", aliceFile, contentTwo)
			charles.StoreFile(aliceFile, []byte(contentTwo))
			userlib.DebugMsg("Doris storing file %s with content: %s", aliceFile, contentTwo)
			doris.StoreFile(aliceFile, []byte(contentTwo))
			userlib.DebugMsg("Eve storing file %s with content: %s", aliceFile, contentTwo)
			eve.StoreFile(aliceFile, []byte(contentTwo))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			err = frank.AcceptInvitation("alice", invite, frankFile)
			Expect(err).ToNot(BeNil())
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Charles for file %s, and Charles accepting invite under name %s.", aliceFile, charlesFile)
			invite, err = alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())
			err = charles.AcceptInvitation("alice", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Frank for file %s, and Frank accepting invite under name %s.", aliceFile, frankFile)
			invite, err = alice.CreateInvitation(aliceFile, "frank")
			Expect(err).To(BeNil())
			err = frank.AcceptInvitation("alice", invite, frankFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creating invite for Eve for file %s, and Eve accepting invite under name %s.", bobFile, eveFile)
			invite, err = bob.CreateInvitation(bobFile, "eve")
			Expect(err).To(BeNil())
			err = eve.AcceptInvitation("bob", invite, eveFile)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Eve creating invite for grace for file %s, and grace accepting invite under name %s.", eveFile, graceFile)
			invite, err = eve.CreateInvitation(eveFile, "grace")
			Expect(err).To(BeNil())
			err = grace.AcceptInvitation("eve", invite, graceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles creating invite for Charles for file %s, and Doris accepting invite under name %s.", aliceFile, charlesFile)
			invite, err = charles.CreateInvitation(charlesFile, "doris")
			Expect(err).To(BeNil())
			err = doris.AcceptInvitation("charles", invite, dorisFile)
			Expect(err).To(BeNil())
			invite, err = charles.CreateInvitation(charlesFile, "horace")
			Expect(err).To(BeNil())
			err = horace.AcceptInvitation("charles", invite, horaceFile)
			Expect(err).To(BeNil())
			tempinvite, err := charles.CreateInvitation(charlesFile, "ira")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob trying to revoke Eve's access from %s.", bobFile)
			err = bob.RevokeAccess(bobFile, "eve")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice trying to revoke Alice's access from %s.", bobFile)
			err = alice.RevokeAccess(aliceFile, "alice")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that all users have acccess to other file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
			data, err = bob.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))
			data, err = charles.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))
			data, err = doris.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))
			data, err = eve.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))

			userlib.DebugMsg("Checking that Bob lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())
			userlib.DebugMsg("Checking that Eve lost access to the file.")
			_, err = eve.LoadFile(eveFile)
			Expect(err).ToNot(BeNil())
			userlib.DebugMsg("Checking that Grace lost access to the file.")
			_, err = grace.LoadFile(graceFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
			err = eve.AppendToFile(eveFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
			err = grace.AppendToFile(graceFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that Charles can load/append the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Frank can load/append the file.")
			data, err = frank.LoadFile(frankFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))
			err = charles.AppendToFile(charlesFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Doris can load/append the file.")
			data, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
			err = doris.AppendToFile(dorisFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Horace can load/append the file.")
			data, err = horace.LoadFile(horaceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree + contentOne)))
			err = horace.AppendToFile(horaceFile, []byte(""))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that ira can accept the invitation from Charles.")
			err = ira.AcceptInvitation("charles", tempinvite, iraFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Ira can load/append the file.")
			data, err = ira.LoadFile(iraFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree + contentOne)))
			err = horace.AppendToFile(horaceFile, []byte(""))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Frank's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "frank")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Frank can't load/append the file.")
			_, err = frank.LoadFile(frankFile)
			Expect(err).ToNot(BeNil())
			err = frank.AppendToFile(frankFile, []byte(contentThree))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that Charles can load/append the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree + contentOne)))
			err = charles.AppendToFile(charlesFile, []byte(""))
			Expect(err).To(BeNil())
			userlib.DebugMsg("Checking that Doris can load/append the file.")
			data, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree + contentOne)))
			err = doris.AppendToFile(dorisFile, []byte(""))
			Expect(err).To(BeNil())
			userlib.DebugMsg("Checking that Horace can load/append the file.")
			data, err = horace.LoadFile(horaceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree + contentOne)))
			err = horace.AppendToFile(horaceFile, []byte(""))
			Expect(err).To(BeNil())

		})

	})

	Describe("Other Tests", func() { // write tests for when there are multiple devices logging into same account

		Specify("Other Test: Testing for multiple accounts.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentTwo)
			err = alice.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Initializing user Alice again.")
			alice2, err := client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice2.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentTwo)
			err = alice2.StoreFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err = alice.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))

			userlib.DebugMsg("Loading file...")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

		})

	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

	})
})
