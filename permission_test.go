package rbacgo

import (
	"testing"
)
func TestNewPermission(t *testing.T) {
	expectedId := "read:users"

	readPermission := NewPermission(expectedId)

	if readPermission == nil {
		t.Fatalf("Expected NewPermission to return a pointer, returned nil instead")
	}
	if readPermission.permissionId != expectedId {
		t.Errorf("The ID of the permission instance must match expectedId")
	}
}

func TestPermission_Match(t *testing.T) {
	basePermission := NewPermission("delete:users")

	if matches := basePermission.Match("delete:users"); !matches {
		t.Errorf("Expected match to return true for matching IDs, but returned false")
	}
	if matches := basePermission.Match("create:users"); matches {
		t.Errorf("Expected match to return false for matching IDs, but returned true")
	}
}