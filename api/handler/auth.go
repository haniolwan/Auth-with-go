package handler

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/mail"
	"os"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt"
	"github.com/haniolwan/go-quiz/db"
	"golang.org/x/crypto/bcrypt"
)

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

	token, _ := createToken(user)
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
	json.NewEncoder(w).Encode("User registered successfully")
}

type User struct {
	UserId   string `json:"user_id"`
	Username string `json:"username"`
	Email    string `json:"email"`
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

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
