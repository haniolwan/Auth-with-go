package handler

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/haniolwan/go-quiz/db"
)

type User struct {
	UserId   string `json:"user_id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type UserRequestBody struct {
	Name string `json:"name"`
}

type Cookie struct {
	Name    string
	Value   string
	Expires string
}

func ScanRow(rows *sql.Rows) (*User, error) {
	user := new(User)

	err := rows.Scan(&user.UserId,
		&user.Username, &user.Password)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func createToken(user *User) (string, error) {
	secretKey := os.Getenv("SECRET_kEY")

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"user_id": user.UserId, "username": user.Username, "password": user.Password,
		"exp": time.Now().Add(time.Hour * 24).Unix(),
	})

	tokenString, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func LoginUser(w http.ResponseWriter, r *http.Request) {

	var user *User

	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid Request Body", http.StatusBadRequest)
	}

	query := `SELECT * FROM users WHERE username = ?`

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

		user = u
		found = true
		break
	}
	if !found {
		http.Error(w, "User Not Found", http.StatusNotFound)
	}
	defer rows.Close()

	token, _ := createToken(user)
	fmt.Println(token)
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

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode("User signed in successfully")
}
