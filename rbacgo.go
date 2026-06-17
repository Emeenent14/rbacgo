package rbacgo

import (
	"errors"
)

var (
	empty = struct{}{}
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

//add parent 
func (rbac *RBAC[T]) SetParent(parentId, childId T)error{
	if _, exists := rbac.roles[parentId];!exists{
		return errors.New("The parent must be an existing role")
	}
	if _, exists := rbac.roles[childId];!exists{
		return errors.New("The child must be an existing role")
	}
	if _, ok := rbac.parents[childId];!ok{
		rbac.parents[childId] = make(Set[T])
	}
	rbac.parents[childId][parentId] = empty
	return nil
}

//Remove parent
func (rbac *RBAC[T]) RemoveParent(parentId, childId T)error{
	if _,exists := rbac.roles[childId]; !exists{
		return errors.New("The given child role does not exist")
	}
	if _,exists := rbac.roles[parentId]; !exists{
		return errors.New("The given parent role does not exist")
	}
	delete(rbac.parents[childId], parentId)
	return nil
} 