package rbacgo

import (
	"testing"
)
func TestNewRole (t *testing.T){
//ARRANGE => ACT => ASSERT
	//ARRANGE
	writerId := "post:writer"
	//ACT
	writer := NewRole(writerId)
	//ASSERT
	if writer == nil{
		t.Fatalf("The role was not instantiated")
	}
	if writer.roleId != writerId{
		t.Fatal("The created role instance ID property is supposed to match writerID ")
	}
	if writer.permissions == nil {
		t.Errorf("The permissions map must never default to nil")
	}
}

func TestRole_Add(t *testing.T){
	//ARRANGE
	writerId := "post:writer"
	perm := "write:post"
	//ACT
	writer := NewRole(writerId)
	writer.Add(perm)
	//ASSERT
	if _, exists := writer.permissions[perm]; !exists {
		t.Errorf("Expected role to have permission %q, but it was missing", perm)
	}
}

func TestRole_Revoke(t *testing.T){
//ARRANGE
	editorId := "post:editor"
	perm := "edit:post"
//ACT
	editor := NewRole(editorId)
	editor.Add(perm)
	if _,exists := editor.permissions[perm]; exists{
		t.Log("Permission Added")
	}
	editor.Revoke(perm)
//ASSERT
	if _,exists := editor.permissions[perm]; exists{
		t.Errorf("Permission not Revoked!")
	}
	t.Log("Permission revoked successfully")
}

func TestRole_Permissions(t *testing.T){
//ARRANGE => ACT => ASSERT
//ARRANGE
	editorId := "post:editor"

	permEdit := "edit:post"
	permWrite := "write:post" 

//ACT
	editor := NewRole(editorId)

	editor.Add(permEdit)
	if _,exists := editor.permissions[permEdit]; exists{
		t.Log("Permission Added")
	}	
	editor.Add(permWrite)
	if _,exists := editor.permissions[permEdit]; exists{
		t.Log("Permission Added")
	}
	permList,_ := editor.Permissions() 
	if len(permList) != 2 || permList == nil {
		t.Errorf("The permissions were not added peoperly")
	}
}

func TestRole_IsPermitted(t *testing.T){
//ARRANGE
	writerId := "post:writer"
	perm := "write:post"
//ACT
	writer := NewRole(writerId)
	writer.Add(perm)
	if _,exists := writer.permissions[perm]; exists{
		t.Log("Permission Added")
	}
//ASSERT
	if !writer.IsPermitted(perm){
		t.Errorf("IsPermitted should not be nil")
	}
}