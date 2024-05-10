package api

import (
	"fmt"
	"net/http"
	"net/smtp"
	"os"
	"strings"
)

func SendVerificationEmail(w http.ResponseWriter, r *http.Request) {

	// Generate random token for user

	recipient := r.URL.Query().Get("email")

	if recipient == "" {
		http.Error(w, "Missing email parameter", http.StatusBadRequest)
	}

	var secretPassword = os.Getenv("SECRET_PASSWORD")

	smtpHost := "smtp.gmail.com"
	smtpPort := 587
	username := "heenoow@gmail.com"

	// Set email parameters
	from := "heenoow@gmail.com"
	to := []string{recipient}
	subject := "Confirm your email"

	htmlTemplate, _ := os.ReadFile("template/email.html")
	var action = "Verify Email"
	var website = "https://quiz.com"

	token, _ := CreateToken(map[string]string{
		"email": recipient,
	})

	var verify_link = "https://quiz.com/" + token

	replacements := map[string]string{
		"{{website}}":     website,
		"{{action}}":      action,
		"{{verify_link}}": verify_link,
	}
	emailContent := string(htmlTemplate)

	for placeholder, replacement := range replacements {
		emailContent = strings.Replace(string(htmlTemplate), placeholder, replacement, -1)
	}

	// Compose the email message
	message := []byte("To: " + to[0] + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/html; charset=\"utf-8\"\r\n" +
		"\r\n" +
		emailContent)

	// Connect to the SMTP server
	auth := smtp.PlainAuth("", username, secretPassword, smtpHost)
	err := smtp.SendMail(fmt.Sprintf("%s:%d", smtpHost, smtpPort), auth, from, to, message)

	if err != nil {
		http.Error(w, "Error sending verification email: "+err.Error(), http.StatusInternalServerError)
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Verification email sent to %s", recipient)
}
