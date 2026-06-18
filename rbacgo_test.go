package rbacgo

import (
	"sync"
	"testing"
	"time"
)

// --- AddRole / RevokeRole / ListRoles ---

func TestAddRole(t *testing.T) {
	rbac := NewRBAC[string]()

	if err := rbac.AddRole(NewRole[string]("admin")); err != nil {
		t.Fatalf("expected no error adding new role, got %v", err)
	}

	if err := rbac.AddRole(NewRole[string]("admin")); err == nil {
		t.Fatal("expected error when adding a duplicate role, got nil")
	}
}

func TestRevokeRole(t *testing.T) {
	rbac := NewRBAC[string]()
	rbac.AddRole(NewRole[string]("editor"))

	if err := rbac.RevokeRole("editor"); err != nil {
		t.Fatalf("expected no error revoking existing role, got %v", err)
	}

	if err := rbac.RevokeRole("editor"); err == nil {
		t.Fatal("expected error when revoking a role that no longer exists, got nil")
	}
}

func TestListRoles(t *testing.T) {
	rbac := NewRBAC[string]()
	rbac.AddRole(NewRole[string]("admin"))
	rbac.AddRole(NewRole[string]("editor"))
	rbac.AddRole(NewRole[string]("viewer"))

	roles := rbac.ListRoles()
	if len(roles) != 3 {
		t.Fatalf("expected 3 roles, got %d", len(roles))
	}

	seen := make(map[string]bool)
	for _, r := range roles {
		seen[r] = true
	}
	for _, want := range []string{"admin", "editor", "viewer"} {
		if !seen[want] {
			t.Errorf("expected role %q to be listed", want)
		}
	}
}

func TestListRoles_Empty(t *testing.T) {
	rbac := NewRBAC[string]()
	roles := rbac.ListRoles()
	if len(roles) != 0 {
		t.Fatalf("expected 0 roles on a fresh RBAC, got %d", len(roles))
	}
}

// --- SetParent / RemoveParent ---

func TestSetParent(t *testing.T) {
	rbac := NewRBAC[string]()
	rbac.AddRole(NewRole[string]("admin"))
	rbac.AddRole(NewRole[string]("editor"))

	if err := rbac.SetParent("admin", "editor"); err != nil {
		t.Fatalf("expected no error setting valid parent, got %v", err)
	}
}

func TestSetParent_MissingParent(t *testing.T) {
	rbac := NewRBAC[string]()
	rbac.AddRole(NewRole[string]("editor"))

	if err := rbac.SetParent("admin", "editor"); err == nil {
		t.Fatal("expected error when parent role does not exist, got nil")
	}
}

func TestSetParent_MissingChild(t *testing.T) {
	rbac := NewRBAC[string]()
	rbac.AddRole(NewRole[string]("admin"))

	if err := rbac.SetParent("admin", "editor"); err == nil {
		t.Fatal("expected error when child role does not exist, got nil")
	}
}

func TestRemoveParent(t *testing.T) {
	rbac := NewRBAC[string]()
	rbac.AddRole(NewRole[string]("admin"))
	rbac.AddRole(NewRole[string]("editor"))
	rbac.SetParent("admin", "editor")

	if err := rbac.RemoveParent("admin", "editor"); err != nil {
		t.Fatalf("expected no error removing existing parent link, got %v", err)
	}

	// Removing again should be a no-op, not an error, since both roles still exist.
	if err := rbac.RemoveParent("admin", "editor"); err != nil {
		t.Fatalf("expected no error removing an already-absent parent link, got %v", err)
	}
}

func TestRemoveParent_MissingRoles(t *testing.T) {
	rbac := NewRBAC[string]()
	rbac.AddRole(NewRole[string]("editor"))

	if err := rbac.RemoveParent("admin", "editor"); err == nil {
		t.Fatal("expected error when parent role does not exist, got nil")
	}

	rbac2 := NewRBAC[string]()
	rbac2.AddRole(NewRole[string]("admin"))

	if err := rbac2.RemoveParent("admin", "editor"); err == nil {
		t.Fatal("expected error when child role does not exist, got nil")
	}
}

// --- IsGranted ---

func TestIsGranted_DirectPermission(t *testing.T) {
	rbac := NewRBAC[string]()
	viewer := NewRole[string]("viewer")
	viewer.Add("read")
	rbac.AddRole(viewer)

	if !rbac.IsGranted("viewer", "read") {
		t.Error("expected viewer to be granted 'read'")
	}
	if rbac.IsGranted("viewer", "write") {
		t.Error("expected viewer NOT to be granted 'write'")
	}
}

func TestIsGranted_InheritedFromParent(t *testing.T) {
	rbac := NewRBAC[string]()

	admin := NewRole[string]("admin")
	admin.Add("write")
	rbac.AddRole(admin)

	editor := NewRole[string]("editor")
	rbac.AddRole(editor)

	// editor inherits from admin
	if err := rbac.SetParent("admin", "editor"); err != nil {
		t.Fatalf("unexpected error setting parent: %v", err)
	}

	if !rbac.IsGranted("editor", "write") {
		t.Error("expected editor to inherit 'write' permission from admin parent")
	}
}

func TestIsGranted_MultiLevelHierarchy(t *testing.T) {
	rbac := NewRBAC[string]()

	superAdmin := NewRole[string]("superadmin")
	superAdmin.Add("delete")
	rbac.AddRole(superAdmin)

	admin := NewRole[string]("admin")
	rbac.AddRole(admin)

	editor := NewRole[string]("editor")
	rbac.AddRole(editor)

	// editor -> admin -> superadmin
	rbac.SetParent("superadmin", "admin")
	rbac.SetParent("admin", "editor")

	if !rbac.IsGranted("editor", "delete") {
		t.Error("expected editor to inherit 'delete' transitively through admin -> superadmin")
	}
}

func TestIsGranted_RemovedParentLosesPermission(t *testing.T) {
	rbac := NewRBAC[string]()

	admin := NewRole[string]("admin")
	admin.Add("write")
	rbac.AddRole(admin)

	editor := NewRole[string]("editor")
	rbac.AddRole(editor)

	rbac.SetParent("admin", "editor")
	if !rbac.IsGranted("editor", "write") {
		t.Fatal("expected editor to be granted 'write' before parent removal")
	}

	rbac.RemoveParent("admin", "editor")
	if rbac.IsGranted("editor", "write") {
		t.Error("expected editor to lose 'write' after parent link removed")
	}
}

func TestIsGranted_NonexistentRole(t *testing.T) {
	rbac := NewRBAC[string]()
	if rbac.IsGranted("ghost", "read") {
		t.Error("expected IsGranted to return false for a role that was never added")
	}
}

func TestIsGranted_RevokedPermission(t *testing.T) {
	rbac := NewRBAC[string]()
	viewer := NewRole[string]("viewer")
	viewer.Add("read")
	rbac.AddRole(viewer)

	viewer.Revoke("read")
	if rbac.IsGranted("viewer", "read") {
		t.Error("expected viewer NOT to be granted 'read' after it was revoked")
	}
}

// TestIsGranted_CyclicHierarchy ensures the DFS visited-set guards against
// infinite recursion when two roles end up as parents of one another.
func TestIsGranted_CyclicHierarchy(t *testing.T) {
	rbac := NewRBAC[string]()

	a := NewRole[string]("a")
	rbac.AddRole(a)

	b := NewRole[string]("b")
	b.Add("perm")
	rbac.AddRole(b)

	// Create a cycle: a -> b -> a
	rbac.SetParent("b", "a")
	rbac.SetParent("a", "b")

	done := make(chan bool, 1)
	go func() {
		done <- rbac.IsGranted("a", "perm")
		close(done)
	}()

	select {
	case granted := <-done:
		if !granted {
			t.Error("expected 'a' to be granted 'perm' via cyclic parent 'b'")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("IsGranted appears to hang on a cyclic role hierarchy (infinite recursion)")
	}
}

// --- Concurrency smoke test (run with -race) ---

func TestRBAC_ConcurrentAccess(t *testing.T) {
	rbac := NewRBAC[int]()
	for i := 0; i < 20; i++ {
		role := NewRole[int](i)
		role.Add(i * 100)
		rbac.AddRole(role)
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			rbac.IsGranted(id, id*100)
			rbac.ListRoles()
		}(i)
	}
	wg.Wait()
}