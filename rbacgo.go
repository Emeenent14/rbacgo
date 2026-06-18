package rbacgo

import (
	"errors"
	"sync"
)

var (
	empty = struct{}{}
)

type Roles[T comparable] map[T]*Role[T]
type Set[T comparable] map[T]struct{}

type RBAC[T comparable] struct {
	roles Roles[T]
	parents map[T]Set[T]
	mu sync.RWMutex
}

func NewRBAC[T comparable]() *RBAC[T] {
	return &RBAC[T]{
		roles: make(Roles[T]),
		parents: make(map[T]Set[T]),
	}
}

//Add role
func (rbac *RBAC[T]) AddRole(role *Role[T]) error {
	rbac.mu.Lock()
	defer rbac.mu.Unlock()

	if _, exists := rbac.roles[role.roleId]; !exists {
		rbac.roles[role.roleId] = role
		return nil
	}
	return errors.New("This role already exists")
}

//Revoke role
func (rbac *RBAC[T]) RevokeRole(roleId T)error{
	rbac.mu.Lock()
	defer rbac.mu.Unlock()

	if _, exists := rbac.roles[roleId]; !exists{
		return errors.New("The role does not exist")
	}
	delete(rbac.roles, roleId)
	return nil
}

//List all role 
func (rbac *RBAC[T]) ListRoles() []T{
	rbac.mu.RLock()
	defer rbac.mu.RUnlock()

	roleSlice := make([]T, 0, len(rbac.roles))
	for role := range rbac.roles{
		roleSlice = append(roleSlice, role)
	}
	return roleSlice
}

//add parent 
func (rbac *RBAC[T]) SetParent(parentId, childId T)error{
	rbac.mu.Lock()
	defer rbac.mu.Unlock()

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
	rbac.mu.Lock()
	defer rbac.mu.Unlock()

	if _,exists := rbac.roles[childId]; !exists{
		return errors.New("The given child role does not exist")
	}
	if _,exists := rbac.roles[parentId]; !exists{
		return errors.New("The given parent role does not exist")
	}
	delete(rbac.parents[childId], parentId)
	return nil
} 

func (rbac *RBAC[T]) IsGranted(r T, permission T) bool {
	rbac.mu.RLock()
	defer rbac.mu.RUnlock()
	
	visited := make(map[T]struct{})
	return rbac.isGrantedDFS(r, permission, visited)
}

//Check permission (depth first search)
// Check permission (depth first search)
func (rbac *RBAC[T]) isGrantedDFS(r T, permission T, visited map[T]struct{}) bool {
	if _, exists := visited[r]; exists {
		return false
	}
	visited[r] = struct{}{}

	role, exists := rbac.roles[r]
	// FIX: Only return early if the role actually HAS the permission.
	if exists && role.IsPermitted(permission) {
		return true
	}

	// If we got here, the current role didn't have it. Check its parents.
	// Renamed 'subrole' to 'parent' for architectural clarity.
	for parent := range rbac.parents[r] {
		if rbac.isGrantedDFS(parent, permission, visited) {
			return true
		}
	}
	return false
}