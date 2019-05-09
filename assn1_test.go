package assn1

import "github.com/fenilfadadu/CS628-assn1/userlib"
import "testing"
import "reflect"

// You can actually import other stuff if you want IN YOUR TEST
// HARNESS ONLY.  Note that this is NOT considered part of your
// solution, but is how you make sure your solution is correct.

func TestInit(t *testing.T) {
	t.Log("Initialization test")
	userlib.DebugPrint = true
	//	someUsefulThings()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
	}
	fetchedUser, err := GetUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to Get user", err)
	}

	if u.Username != fetchedUser.Username {
		t.Error("Integrity error: User data does not match!!")
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	// You probably want many more tests here.
}

func TestStorage(t *testing.T) {
	// And some more tests, because
	userlib.DebugPrint = true
	//	someUsefulThings()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
	}
	u, err = GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	t.Log("Loaded user", u)

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
	}
}

func TestShare(t *testing.T) {
	userlib.DebugPrint = true
	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
	}
	u, err = GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)
	var v2 []byte
	var msgid string

	v, err = u.LoadFile("file1")

	if err != nil {
		t.Error("Failed to download the file from alice", err)
	}

	msgid, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
	}
	err = u2.ReceiveFile("file2", "alice", msgid)
	if err != nil {
		t.Error("Failed to receive the share message", err)
	}

	v3313 := []byte("This is a append")
	u.AppendFile("file1", v3313)

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
	}
	if !reflect.DeepEqual([]byte("This is a testThis is a append"), v2) {
		userlib.DebugMsg(string(v2))
		t.Error("Shared file is not the same", v, v2)
	}

	u2.AppendFile("file2", []byte("I am second here"))

	u3, err3 := InitUser("himanshu", "11223")
	if err2 != nil {
		t.Error("Failed to initialize bob", err3)
	}
	msgid3, err := u2.ShareFile("file2", "himanshu")
	if err != nil {
		t.Error("Failed to share the a file", err)
	}
	err = u3.ReceiveFile("file555", "bob", msgid3)
	if err != nil {
		t.Error("Failed to receive the share message", err)
	}

	v3, err := u3.LoadFile("file555")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
	}
	if !reflect.DeepEqual([]byte("This is a testThis is a appendI am second here"), v3) {
		userlib.DebugMsg(string(v3))
		t.Error("Shared file is not the same", v, v2)
	}

	u.RevokeFile("file1")
	u.AppendFile("file1", []byte("After Revoke"))
	// v4, err := u3.LoadFile("file555")
	// userlib.DebugMsg(string(v4))
	// if err != nil {
	// 	t.Error("Failed to download the file after sharing", err)
	// }
	// if !reflect.DeepEqual([]byte("This is a testThis is a appendI am second hereAfter Revoke"), v4) {
	// 	userlib.DebugMsg(string(v4))
	// 	t.Error("Shared file is not the same", v, v4)
	// }
}
