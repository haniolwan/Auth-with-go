package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

type User struct {
	ID    string
	Name  string
	Token string `json:"group,omitempty" bson:",omitempty"`
}

func loginUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var user User
	err := json.NewDecoder(r.Body).Decode(user)

	if err != nil {
		http.Error(w, "Invalid Request Body", http.StatusBadRequest)
	}

	// verify user auth

	w.WriteHeader(http.StatusContinue)
	json.NewEncoder(w).Encode("User signed in successfully")
}
func main() {

	http.HandleFunc("/login", loginUser)
	// Run Server
	fmt.Println("Quiz app server is running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
