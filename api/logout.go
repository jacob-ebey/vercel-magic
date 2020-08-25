package logout

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/jacob-ebey/magic/admin"
)

// Handler is the main entrypoint for the route "api/logout"
func Handler(w http.ResponseWriter, r *http.Request) {
	// Only allow post requests
	if r.Method != http.MethodPost {
		http.Error(w, "{ \"error\": \"Method not allowed\" }", http.StatusMethodNotAllowed)
		return
	}

	// Initialize your admin client
	magic, err := admin.NewMagicAdmin(os.Getenv("MAGIC_SECRET"))
	if err != nil {
		// Log errors somewhere you have access to
		fmt.Println("{ \"error\": \"Error initialising magic admin\" }", err.Error())

		http.Error(w, "{ \"error\": \"Error initializing handler\" }", http.StatusInternalServerError)
		return
	}

	cookie, err := r.Cookie("api_token")
	if err != nil {
		http.Error(w, "{ \"error\": \"Not logged in\" }", http.StatusForbidden)
		return
	}

	token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(os.Getenv("ENCRYPTION_SECRET")), nil
	})
	if err != nil {
		http.Error(w, "{ \"error\": \"Could not decode token\" }", http.StatusForbidden)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(w, "{ \"error\": \"Could not decode claims\" }", http.StatusForbidden)
		return
	}

	if err := magic.LogoutByIssuer(claims["issuer"].(string)); err != nil {
		http.Error(w, "{ \"error\": \"Error logging you out\" }", http.StatusForbidden)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "api_token",
		Value:    "",
		Expires:  time.Unix(0, 0),
		MaxAge:   0,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	w.Write([]byte("{ \"success\": true }"))
}
