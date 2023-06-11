package model

type GetUserByIdReqUri struct {
	ID int64 `uri:"id"`
}

type AddNewUserReqBody struct {
	Name string `json:"name"`
}

type DeleteUserReqUri struct {
	ID int64 `uri:"id"`
}

type NewUser struct {
	Name     string `json:"name" binding:"required"`
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
}
