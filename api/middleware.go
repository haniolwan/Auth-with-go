package api

import (
	"net/http"
)

func Auth(HandlerFunc http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")

		cookie, _ := r.Cookie("user_token")

		err := VerifyToken(cookie.Value)

		if err != nil {
			JsonResponse(w, http.StatusUnauthorized, "401 Unauthorized - Access Denied")
			return
		}

		HandlerFunc.ServeHTTP(w, r) // final line if success
	}
}
