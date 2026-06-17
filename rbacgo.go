package rbacgo

import "fmt"

type Roles[T comparable] map[T]*Role[T]

type rbacgo[T comparable] struct {
	roles   Roles[T]
	parents map[T]map[T]struct{}
}

func NewRbac[T comparable]() *rbacgo[T] {
	return &rbacgo[T]{
		roles:   make(map[T]*Role[T]),
		parents: make(map[T]map[T]struct{}),
	}
}

//Add role
func (rbac *rbacgo[T]) AddRole(role *Role[T]){
	rbac.roles[role.roleId] = role	
}

//Remove role
func (rbac *rbacgo[T]) RemoveRole(roleId T){
	delete(rbac.roles, roleId)
}		

//List roles
func (rbac *rbacgo[T]) ListRoles() []T{
	roleList := make([]T, 0, len(rbac.roles))	
	for roleId := range rbac.roles{
		roleList = append(roleList, roleId)
	}	
	return roleList
}