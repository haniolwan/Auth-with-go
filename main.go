package main

import (
	"fmt"
	"log"
	"net/http"

	api "github.com/haniolwan/go-quiz/api"
	"github.com/joho/godotenv"
)

func main() {
	godotenv.Load(".env")

	http.HandleFunc("/login", api.LoginUser)
	http.HandleFunc("/register", api.RegisterUser)

	http.HandleFunc("/home", api.Auth(api.Home))

	http.HandleFunc("/send_verification_email", api.SendVerificationEmail)

	// Run Server
	fmt.Println("Quiz app server is running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
