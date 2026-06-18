package rbacgo

import (
	"errors"
	"sync"
)

var (
	empty = struct{}{}
)

// Roles maps role identifiers to their corresponding Role structures.
type Roles[T comparable] map[T]*Role[T]

// Set implements a standard set collection using map keys.
type Set[T comparable] map[T]struct{}

// RBAC represents the core Role-Based Access Control system,
// managing roles, parent-child inheritance relationships, and permission checks.
// It is safe for concurrent use.
type RBAC[T comparable] struct {
	roles   Roles[T]
	parents map[T]Set[T]
	mu      sync.RWMutex
}

// NewRBAC initializes and returns a new RBAC system.
func NewRBAC[T comparable]() *RBAC[T] {
	return &RBAC[T]{
		roles:   make(Roles[T]),
		parents: make(map[T]Set[T]),
	}
}

// AddRole registers a new role in the RBAC system.
// It returns an error if the role ID is already registered.
func (rbac *RBAC[T]) AddRole(role *Role[T]) error {
	rbac.mu.Lock()
	defer rbac.mu.Unlock()

	if rbac.roles == nil {
		rbac.roles = make(Roles[T])
	}
	if _, exists := rbac.roles[role.roleId]; !exists {
		rbac.roles[role.roleId] = role
		return nil
	}
	return errors.New("This role already exists")
}

// RevokeRole removes a role from the RBAC system.
// It returns an error if the role ID does not exist.
func (rbac *RBAC[T]) RevokeRole(roleId T) error {
	rbac.mu.Lock()
	defer rbac.mu.Unlock()

	if _, exists := rbac.roles[roleId]; !exists {
		return errors.New("The role does not exist")
	}
	delete(rbac.roles, roleId)
	return nil
}

// ListRoles returns a slice containing the IDs of all registered roles.
func (rbac *RBAC[T]) ListRoles() []T {
	rbac.mu.RLock()
	defer rbac.mu.RUnlock()

	roleSlice := make([]T, 0, len(rbac.roles))
	for role := range rbac.roles {
		roleSlice = append(roleSlice, role)
	}
	return roleSlice
}

// SetParent establishes an inheritance relationship where childId inherits
// permissions from parentId. Both roles must already exist in the RBAC system.
func (rbac *RBAC[T]) SetParent(parentId, childId T) error {
	rbac.mu.Lock()
	defer rbac.mu.Unlock()

	if _, exists := rbac.roles[parentId]; !exists {
		return errors.New("The parent must be an existing role")
	}
	if _, exists := rbac.roles[childId]; !exists {
		return errors.New("The child must be an existing role")
	}
	if _, ok := rbac.parents[childId]; !ok {
		rbac.parents[childId] = make(Set[T])
	}
	rbac.parents[childId][parentId] = empty
	return nil
}

// RemoveParent breaks the inheritance link between parentId and childId.
// It returns an error if either role does not exist.
func (rbac *RBAC[T]) RemoveParent(parentId, childId T) error {
	rbac.mu.Lock()
	defer rbac.mu.Unlock()

	if _, exists := rbac.roles[childId]; !exists {
		return errors.New("The given child role does not exist")
	}
	if _, exists := rbac.roles[parentId]; !exists {
		return errors.New("The given parent role does not exist")
	}
	delete(rbac.parents[childId], parentId)
	return nil
}

// IsGranted checks whether a role (or any of its inherited parent roles) has been
// granted the specified permission. It performs a cycle-safe search.
func (rbac *RBAC[T]) IsGranted(r T, permission T) bool {
	rbac.mu.RLock()
	defer rbac.mu.RUnlock()

	visited := make(map[T]struct{})
	return rbac.isGrantedDFS(r, permission, visited)
}

// isGrantedDFS performs a depth-first search through the role hierarchy
// to check if a permission is granted, guarding against cycle detection.
func (rbac *RBAC[T]) isGrantedDFS(r T, permission T, visited map[T]struct{}) bool {
	if _, exists := visited[r]; exists {
		return false
	}
	visited[r] = struct{}{}

	role, exists := rbac.roles[r]
	if exists && role.IsPermitted(permission) {
		return true
	}

	for parent := range rbac.parents[r] {
		if rbac.isGrantedDFS(parent, permission, visited) {
			return true
		}
	}
	return false
}