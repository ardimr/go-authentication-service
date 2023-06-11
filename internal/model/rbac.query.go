package model

type RawRolePermission struct {
	RoleName    string `json:"role_name"`
	Permissions []byte `json:"permissions"`
}

type RolePermission struct {
	RoleName    string               `json:"role_name"`
	Permissions []ResourcePermission `json:"permissions"`
}

type ResourcePermission struct {
	ResourceName string   `json:"resource"`
	Actions      []string `json:"actions"`
}

type Role struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

type Resource struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}
