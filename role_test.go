package rbacgo

import (
	"testing"
)
func TestNewRole(t *testing.T) {
	writerId := "post:writer"
	writer := NewRole(writerId)
	if writer == nil {
		t.Fatalf("The role was not instantiated")
	}
	if writer.roleId != writerId {
		t.Fatal("The created role instance ID property is supposed to match writerId")
	}
	if writer.permissions == nil {
		t.Errorf("The permissions map must never default to nil")
	}
}

func TestRole_Add(t *testing.T) {
	writerId := "post:writer"
	perm := "write:post"
	writer := NewRole(writerId)
	writer.Add(perm)
	if _, exists := writer.permissions[perm]; !exists {
		t.Errorf("Expected role to have permission %q, but it was missing", perm)
	}
}

func TestRole_Revoke(t *testing.T) {
	editorId := "post:editor"
	perm := "edit:post"
	editor := NewRole(editorId)
	editor.Add(perm)
	if _, exists := editor.permissions[perm]; exists {
		t.Log("Permission Added")
	}
	editor.Revoke(perm)
	if _, exists := editor.permissions[perm]; exists {
		t.Errorf("Permission not Revoked!")
	}
	t.Log("Permission revoked successfully")
}

func TestRole_Permissions(t *testing.T) {
	editorId := "post:editor"

	permEdit := "edit:post"
	permWrite := "write:post"

	editor := NewRole(editorId)

	editor.Add(permEdit)
	if _, exists := editor.permissions[permEdit]; exists {
		t.Log("Permission Added")
	}
	editor.Add(permWrite)
	if _, exists := editor.permissions[permEdit]; exists {
		t.Log("Permission Added")
	}
	permList, _ := editor.Permissions()
	if len(permList) != 2 || permList == nil {
		t.Errorf("The permissions were not added properly")
	}
}

func TestRole_IsPermitted(t *testing.T) {
	writerId := "post:writer"
	perm := "write:post"
	writer := NewRole(writerId)
	writer.Add(perm)
	if _, exists := writer.permissions[perm]; exists {
		t.Log("Permission Added")
	}
	if !writer.IsPermitted(perm) {
		t.Errorf("IsPermitted should not be nil")
	}
}