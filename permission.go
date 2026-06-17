package rbacgo

import ("fmt"
		"errors"
)

type permission[T comparable] struct{
	permissionId T
}

func NewPermission(permission T) *permssion[T] {
	return &permission[T]{permissionId : permission}
}

// match
func (perm *permission[T comparable]) Match(OtherPerm T)bool{
	perm.permissionId == OtherPerm
}