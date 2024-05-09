package api

import (
	"fmt"
	"net/http"
)

func Home(w http.ResponseWriter, r *http.Request) {
	// Set the content type header to text/html
	w.Header().Set("Content-Type", "text/html")

	// Write the HTML response to the response writer
	fmt.Fprint(w, "<html><body><h1>Hello, World!</h1></body></html>")
}
