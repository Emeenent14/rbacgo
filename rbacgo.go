package rbacgo

import "fmt"

type Roles[T comparable] map[T]*Role[T]

type rbacgo struct {
	roles Roles[T]
	parents map[T]map[T]struct{}
}

func NewRbac(role *Role[T]) Roles[T]{
	return &rbacgo{
		roles: make(map[T]*Role[T]),
		parents: make(map[T]map[T]struct{}),
	}
}

//Add role
func (rbac *rbacgo) AddRole(role *Role[T]){
	rbac.roles[role.roleId] = role	
}

//Remove role
func (rbac *rbacgo) RemoveRole(roleId T){
	delete(rbac.roles, roleId)
}		

//List roles
func (rbac *rbacgo) ListRoles() []T{
	roleList := make([]T, 0, len(rbac.roles))	
	for roleId := range rbac.roles{
		append(roleList, roleId)
	}	
	return roleList
}






