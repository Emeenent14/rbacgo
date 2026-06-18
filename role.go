package rbacgo

import (
	"errors"
)

// Fixed typo in name and made it consistent
type permission[T comparable] map[T]struct{}

type Role[T comparable] struct {
	roleId      T
	permissions permission[T] // Added [T]
}

// Added [T comparable] to the function signature
func NewRole[T comparable](roleId T) *Role[T] {
	return &Role[T]{
		roleId:      roleId,
		permissions: make(permission[T]),
	}
}

// Add permission (Changed receiver to 'r')
func (r *Role[T]) Add(perm T) {
	if r.permissions == nil {
		r.permissions = make(permission[T])
	}
	r.permissions[perm] = struct{}{}
}

// Revoke permission
func (r *Role[T]) Revoke(perm T) {
	if r.permissions != nil {
		delete(r.permissions, perm)
	}
}

// List permissions (Flipped return order to match Go standards)
func (r *Role[T]) Permissions() ([]T, error) {
	if len(r.permissions) == 0 {//len returns ZERO for a nil map
		return nil, errors.New("there are no permissions here")
	}

	permissionsList := make([]T, 0, len(r.permissions))
	for perm := range r.permissions {
		permissionsList = append(permissionsList, perm) // Fixed append assignment
	}
	return permissionsList, nil
}

// Check if user has a permission
func (r *Role[T]) IsPermitted(perm T) bool {
	if r.permissions == nil {
		return false
	}
	_, exists := r.permissions[perm]
	return exists
}


//identifiers should be named using camelCase as opposed to types which should
//be named using PascalCase. Also, the struct name should be capitalized to make 
// it public and accessible outside the package.

//when handling errors using multiple retunn values, the error should be the last return value. 
//This is a common convention in Go and helps to improve readability and consistency across codebases.