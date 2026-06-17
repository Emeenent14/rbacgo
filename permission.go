package rbacgo

type Permission[T comparable] struct{
	permissionId T
}

func NewPermission[T comparable](permission T) *Permission[T] {
	return &Permission[T]{permissionId : permission}
}

// match
func (perm *Permission[T]) Match(Other T)bool{
	return perm.permissionId == Other
}