package api

import (
	"fmt"
	"net/http"
)

func Auth(HandlerFunc http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")

		cookie, _ := r.Cookie("user_token")

		err := verifyToken(cookie.Value)

		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "401 Unauthorized - Access Denied")
			return
		}

		HandlerFunc.ServeHTTP(w, r) // final line if success

	}
}
