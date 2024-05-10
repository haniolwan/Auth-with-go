package api

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
	str "github.com/haniolwan/go-quiz/store"
	"golang.org/x/crypto/bcrypt"
)

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

	token, _ := CreateToken(map[string]string{
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

	token, _ := CreateToken(map[string]string{
		"user_id":  user.UserId,
		"username": user.Username,
		"password": user.Password,
	})

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

func AuthUserMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		cookie, _ := r.Cookie("user_token")

		fmt.Println(cookie)
		// query := `SELECT * FROM users WHERE username = ?`

		if true {

		} else {
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}
	})
}

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

func ScanRow(rows *sql.Rows) (*User, error) {
	user := new(User)

	err := rows.Scan(&user.Username, &user.Password)
	if err != nil {
		return nil, err
	}
	return user, nil
}

var secretKey = os.Getenv("SECRET_kEY")

func CreateToken(params map[string]string) (string, error) {

	claims := jwt.MapClaims{
		"exp": time.Now().Add(time.Hour * 24).Unix(),
	}

	for key, value := range params {
		claims[key] = value
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func verifyToken(tokenString string) error {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secretKey), nil
	})
	if err != nil {
		return err
	}

	if !token.Valid {
		return fmt.Errorf("invalid token")
	}

	return nil
}
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
