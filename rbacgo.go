package rbacgo

import (
	"errors"
)

type Roles[T comparable] map[T]*Role[T]
type Set[T comparable] map[T]struct{}

type RBAC[T comparable] struct {
	roles Roles[T]
	parents map[T]Set[T]
}

func NewRBAC[T comparable]() *RBAC[T] {
	return &RBAC[T]{
		roles: make(Roles[T]),
		parents: make(map[T]Set[T]),
	}
}

//Add role
func (rbac *RBAC[T]) AddRole(role *Role[T]) error {
	if _, exists := rbac.roles[role.roleId]; !exists {
		rbac.roles[role.roleId] = role
		return nil
	}
	return errors.New("This role already exists")
}

//Revoke role
func (rbac *RBAC[T]) RevokeRole(roleId T)error{
	if _, exists := rbac.roles[roleId]; !exists{
		return errors.New("The role does not exist")
	}
	delete(rbac.roles, roleId)
	return nil
}

//List all role 
func (rbac *RBAC[T]) ListRoles() []T{
	roleSlice := make([]T, 0, len(rbac.roles))
	for role := range rbac.roles{
		roleSlice = append(roleSlice, role)
	}
	return roleSlice
}