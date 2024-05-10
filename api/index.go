package api

import (
	"net/http"
)

func Home(w http.ResponseWriter, r *http.Request) {
	// Set the content type header to text/html
	w.Header().Set("Content-Type", "text/html")

	// Write the HTML response to the response writer
	// fmt.Fprint(w, "<html><body><h1>Hello, World!</h1></body></html>")
	// var apiKey = os.Getenv("MailGUN_API_KEY")
	// var domain = os.Getenv("MailGUN_DOMAIN")
}
