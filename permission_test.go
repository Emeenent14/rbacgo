package rbacgo

import (
	"testing"
)
func TestNewPermission (t *testing.T){
//ARRANGE → ACT → ASSERT
//Set data → call function → check result

//ARRANGE
expectedId := "read:users"

//ACT
readPermission := NewPermission(expectedId)

//ASSERT
if readPermission == nil {
	t.Fatalf("Expected NewPermission to retrun a pointer, retunnrd nil instead")
}
if readPermission.permissionId != expectedId{
	t.Errorf("The ID of the permission instance must match expectedID")
}
}

func TestPermission_Match(t *testing.T){
//ARRANGE => ACT => ASSERT
//ARRANGE
basePermission := NewPermission("delete:users")

//ACT & ASSERTION
if matches := basePermission.Match("delete:users");!matches{
	t.Errorf("Expected match to return true for matching IDs, but returned false")
}
if matches := basePermission.Match("create:users");matches{
	t.Errorf("Expected match to return false for matching IDs, but returned true")
}

}