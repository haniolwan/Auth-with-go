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

	// Auth
	http.HandleFunc("/login", api.LoginUser)
	http.HandleFunc("/register", api.RegisterUser)
	http.HandleFunc("/send_verification_email", api.RecieveVerifyEmail)
	http.HandleFunc("/verification_email", api.VerifyEmailSubmit)

	// Home
	http.HandleFunc("/home", api.Auth(api.Home))

	// Run Server
	fmt.Println("Quiz app server is running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
