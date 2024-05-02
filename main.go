package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/haniolwan/go-quiz/api/handler"

	"github.com/joho/godotenv"
)

func main() {
	godotenv.Load(".env")

	http.HandleFunc("/login", handler.LoginUser)
	http.HandleFunc("/register", handler.RegisterUser)

	// Run Server
	fmt.Println("Quiz app server is running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
