package rbacgo

import (
	"errors"
	"sync"
)

// permission represents a unique set of permissions.
type permission[T comparable] map[T]struct{}

// Role represents a system role containing a unique set of permissions.
// It is thread-safe.
type Role[T comparable] struct {
	roleId      T
	permissions permission[T]
	mu          sync.RWMutex
}

// NewRole constructs and returns a new Role instance with the specified role ID.
func NewRole[T comparable](roleId T) *Role[T] {
	return &Role[T]{
		roleId:      roleId,
		permissions: make(permission[T]),
	}
}

// Add grants a permission to the role.
func (r *Role[T]) Add(perm T) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.permissions == nil {
		r.permissions = make(permission[T])
	}
	r.permissions[perm] = struct{}{}
}

// Revoke removes a permission from the role.
func (r *Role[T]) Revoke(perm T) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.permissions != nil {
		delete(r.permissions, perm)
	}
}

// Permissions returns a slice of all permissions directly granted to this role.
// It returns an error if the role has no permissions.
func (r *Role[T]) Permissions() ([]T, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if len(r.permissions) == 0 {
		return nil, errors.New("there are no permissions here")
	}

	permissionsList := make([]T, 0, len(r.permissions))
	for perm := range r.permissions {
		permissionsList = append(permissionsList, perm)
	}
	return permissionsList, nil
}

// IsPermitted checks if the role directly possesses the specified permission.
func (r *Role[T]) IsPermitted(perm T) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.permissions == nil {
		return false
	}
	_, exists := r.permissions[perm]
	return exists
}