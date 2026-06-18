package rbacgo

// Permission represents a specific authorization identifier within the RBAC system.
type Permission[T comparable] struct {
	permissionId T
}

// NewPermission creates and returns a new Permission instance.
func NewPermission[T comparable](permission T) *Permission[T] {
	return &Permission[T]{permissionId: permission}
}

// Match checks whether the permission ID matches the provided ID.
func (perm *Permission[T]) Match(other T) bool {
	return perm.permissionId == other
}