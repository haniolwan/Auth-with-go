package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/mail"

	"github.com/go-sql-driver/mysql"
	"github.com/haniolwan/go-quiz/db"
	str "github.com/haniolwan/go-quiz/store"
)

type User struct {
	UserId     string `json:"user_id"`
	Username   string `json:"username" validate:"required"`
	Email      string `json:"email" validate:"required"`
	Password   string `json:"password" validate:"required"`
	IsVerified bool   `json:"isverified" sql:"isverified"`
}

type UserRequestBody struct {
	Name string `json:"name"`
}

type Cookie struct {
	Name    string
	Value   string
	Expires string
}
type contextKey string

const UserKey contextKey = "user_login"

func LoginUser(w http.ResponseWriter, r *http.Request) {

	var user *User

	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid Request Body", http.StatusBadRequest)
	}

	query := `SELECT username,password FROM users WHERE username = ?`

	rows, err := db.DB.Query(query, user.Username)

	if err != nil {
		http.Error(w, "Database Error", http.StatusInternalServerError)
		return
	}

	found := false

	for rows.Next() {
		u, err := ScanRow(rows)
		if err != nil {
			fmt.Println("Error scanning row:", err)
			continue
		}

		var valid = CheckPasswordHash(user.Password, u.Password)
		if !valid {
			http.Error(w, "Password Invalid", http.StatusBadRequest)
			return
		}
		found = true
		break
	}
	if !found {
		http.Error(w, "User Not Found", http.StatusNotFound)
		return
	}

	defer rows.Close()

	token, _, _ := CreateToken(map[string]string{
		"user_id":  user.UserId,
		"username": user.Username,
		"password": user.Password,
	})
	str.NewStore().Set("token_key", token)

	cookie := http.Cookie{
		Name:     "user_token",
		Value:    token,
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	ctx := r.Context()
	ctx = context.WithValue(ctx, UserKey, user)
	r = r.WithContext(ctx)

	http.SetCookie(w, &cookie)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode("User signed in successfully")
}

func RegisterUser(w http.ResponseWriter, r *http.Request) {

	var user *User

	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid Request Body", http.StatusBadRequest)
	}

	if _, err := mail.ParseAddress(user.Email); err != nil {
		http.Error(w, "Invalid Email Address", http.StatusBadRequest)
	}

	if len(user.Password) < 8 {
		http.Error(w, "Invalid Password", http.StatusBadRequest)
	}

	query := "INSERT INTO users (username, email, password) VALUES (?, ?, ?)"

	hashedPassword, _ := HashPassword(user.Password)

	_, err := db.DB.Exec(query, user.Username, user.Email, hashedPassword)

	if err != nil {
		if mysqlErr, ok := err.(*mysql.MySQLError); ok {
			if mysqlErr.Number == 1062 {
				http.Error(w, "User already exists", http.StatusBadRequest)
				return
			}
		}

	}

	token, _, _ := CreateToken(map[string]string{
		"user_id":  user.UserId,
		"username": user.Username,
		"password": user.Password,
	})

	verify_email_query := "INSERT INTO unverified_users (email, verification_token) VALUES (?, ?)"
	_, verifyErr := db.DB.Exec(verify_email_query, user.Email, token)

	if verifyErr != nil {
		http.Error(w, "Cannot verify user", http.StatusBadRequest)
		return
	}

	cookie := http.Cookie{
		Name:     "user_token",
		Value:    token,
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, &cookie)

	// store user in request context
	ctx := r.Context()
	ctx = context.WithValue(ctx, UserKey, user)
	r = r.WithContext(ctx)

	RecieveVerifyEmail(w, r)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode("User registered successfully")
}
