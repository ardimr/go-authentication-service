package model

import "time"

type User struct {
	ID        int64     `json:"id,omitempty"`
	Name      string    `json:"name"`
	Username  string    `json:"username,omitempty"`
	Password  string    `json:"password,omitempty"`
	Email     string    `json:"email"`
	Role      string    `json:"role,omitempty"`
	CreatedAt time.Time `json:"created_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

type UserInfo struct {
	ID          int64    `json:"id,omitempty"`
	Name        string   `json:"Name"`
	Username    string   `json:"Username"`
	Password    string   `json:"password"`
	Email       string   `json:"email"`
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
}

type UserRole struct {
	ID       int64  `json:"id,omitempty"`
	Username string `json:"username"`
	RoleID   int64  `json:"role_id"`
}
