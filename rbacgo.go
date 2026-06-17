package rbacgo

import (
	"errors"
)

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
func (rbac *rbacgo[T]) AddRole(role *Role[T]) error {
	if _, exists := rbac.roles[role.roleId]; !exists {
		rbac.roles[role.roleId] = role
		return nil
	}
	return errors.New("This role already exists")
}

//Remove role
func (rbac *rbacgo[T]) RemoveRole(roleId T) error {
	if _, exists := rbac.roles[roleId]; !exists {
		return errors.New("The role does not exist")
	}
	delete(rbac.roles, roleId)
	return nil
}		

//List roles
func (rbac *rbacgo[T]) ListRoles() []T{
	roleList := make([]T, 0, len(rbac.roles))	
	for roleId := range rbac.roles{
		roleList = append(roleList, roleId)
	}	
	return roleList
}