package rbacgo

import "fmt"

type permssion[T comparable] map[T]struct{}

type Role struct {
	roleId T
	permissions permission
}

func NewRole(Role T) *Role[T]{
	return &Role[T]{
		roleId: Role
		permission : make(map[T]struct{})
	}
}

//Add permission
func (Role *Role[T]) Add(perm T){
	if Role.permissions == nil {
		Role.permissions = make(map[T]struct)
	}
	Role.permissions[perm] = perm 
}

//Revoke permission
func (Role *Role[T]) Revoke(perm T){
	delete(Role.permissions, perm)
}

//list permissions
func (Role *Role[T]) Permissions()(error, []T){
	if Role.permissions == nil {
		return error.New("The are no permissions here"),nil
	}
	if len(Role.permissions) == 0{
		return error.New("The are no permissions here"),nil
	}
	permissionsList := make([]T, 0, len(Role.permissions))
	for perm := range Role.permissions{
		append(permissionList, perm)
	}
	return nil, permissionsList
}

//check if user has a permission
func (Role *Role[T]) IsPermitted(perm T)bool{
	if Role.permissions == nil{
		return false
	}
	_, exists := Role.permissions[perm]
	return exists 
}







