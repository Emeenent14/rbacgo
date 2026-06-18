# rbacgo

A lightweight, thread-safe, and generic Role-Based Access Control (RBAC) library written in Go. enjoy!!

## Features

- **Generic Types**: Fully customizable role and permission identifiers (supports strings, integers, or any custom `comparable` types).
- **Hierarchical Inheritance**: Establish parent-child inheritance relationships between roles (e.g., `editor` inherits from `admin`).
- **Cycle-Safe Evaluation**: Built-in cycle detection protects against infinite recursion in cyclic role graphs during permission evaluation.
- **Thread-Safe**: Safely use the RBAC system across concurrent goroutines (backed by `sync.RWMutex`).

## Installation

```bash
go get github.com/Emeenent14/rbacgo
```

## Quick Start

Here is a quick example of how to create permissions, roles, define role hierarchies, and check access:

```go
package main

import (
	"fmt"
	"github.com/Emeenent14/rbacgo"
)

func main() {
	// 1. Initialize the generic RBAC system with string keys
	rbac := rbacgo.NewRBAC[string]()

	// 2. Create and configure roles
	admin := rbacgo.NewRole("admin")
	admin.Add("write:posts")
	admin.Add("delete:posts")

	editor := rbacgo.NewRole("editor")
	editor.Add("edit:posts")

	viewer := rbacgo.NewRole("viewer")
	viewer.Add("read:posts")

	// 3. Register roles into the RBAC system
	rbac.AddRole(admin)
	rbac.AddRole(editor)
	rbac.AddRole(viewer)

	// 4. Set up parent-child inheritance
	// Here, 'editor' inherits permissions from 'admin',
	// and 'viewer' inherits from 'editor' (transitive permissions).
	rbac.SetParent("admin", "editor")
	rbac.SetParent("editor", "viewer")

	// 5. Query permissions (cycle-safe DFS is performed)
	fmt.Println("Does admin have read:posts?", rbac.IsGranted("admin", "read:posts"))     // false (unless granted explicitly or inherited)
	fmt.Println("Does viewer have delete:posts?", rbac.IsGranted("viewer", "delete:posts")) // true (inherited from admin via editor)
	fmt.Println("Does viewer have edit:posts?", rbac.IsGranted("viewer", "edit:posts"))   // true (inherited from editor)
}
```

## Running Tests

To run the unit tests, execute:

```bash
go test -v ./...
```

## License

This project is licensed under the MIT License.
