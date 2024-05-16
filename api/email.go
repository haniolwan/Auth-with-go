package api

import (
	"fmt"
	"net/http"
	"net/smtp"
	"os"
	"strings"

	"github.com/haniolwan/go-quiz/db"
)

func RecieveVerifyEmail(w http.ResponseWriter, r *http.Request) {

	user, _ := r.Context().Value(UserKey).(User)

	var recipient = r.URL.Query().Get("email")

	var emailToVerify string
	if recipient != "" {
		emailToVerify = recipient
	} else {
		emailToVerify = user.Email
	}

	if err := verifyEmail(emailToVerify); err != nil {
		JsonResponse(w, http.StatusInternalServerError, "Error sending verification email")
	}
	JsonResponse(w, http.StatusOK, fmt.Sprintf("Verification email sent to %s", recipient))

}

func verifyEmail(recipient string) error {
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

	token, _, _ := CreateToken(map[string]string{
		"email": recipient,
	})

	var verify_link = "https://quiz.com/?token=" + token

	replacements := map[string]string{
		"website":     website,
		"action":      action,
		"verify_link": verify_link,
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
	return err

}

func VerifyEmailSubmit(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")

	token := r.URL.Query().Get("token")

	err := VerifyToken(token)

	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, err)
		return
	}

	query := `SELECT verification_token FROM unverified_users WHERE email = ?`

	rows, _ := db.DB.Query(query, email)

	var verification_token = ""

	for rows.Next() {
		err := rows.Scan(&verification_token)

		if err != nil {
			fmt.Println("Error scanning row:", err)
			continue
		}

		if verification_token != "" {

			update_is_verify_query := "UPDATE users SET is_verified = TRUE WHERE email = ?"

			db.DB.Exec(update_is_verify_query, email)

			deleteQuery := "DELETE FROM unverified_users WHERE email = ?"

			db.DB.Exec(deleteQuery, email)

			JsonResponse(w, http.StatusOK, "User successfully verified")
		}
	}

}
