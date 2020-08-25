package login

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/jacob-ebey/magic/admin"
)

var ttl = 60 * 60 * 8

// Handler is the main entrypoint for the route "api/login"
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

	// Get the token from the headers
	authorization := r.Header.Get("authorization")
	did := strings.Trim(strings.Split(authorization, "Bearer")[0], " ")

	// Get metadata for the user
	user, err := magic.GetMetadataByToken(did)
	if err != nil {
		// Log errors somewhere you have access to
		fmt.Println("Error logging user in", err.Error())

		http.Error(w, "{ \"error\": \"Could not log you in :(\" }", http.StatusForbidden)
		return
	}

	// Create a jwt token for use with api routes
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email":         user.Email,
		"issuer":        user.Issuer,
		"publicAddress": user.PublicAddress,
	})
	apiToken, err := token.SignedString([]byte(os.Getenv("ENCRYPTION_SECRET")))

	// Store it in a cookie for the browser
	expires := time.Now().Add(time.Duration(ttl))
	http.SetCookie(w, &http.Cookie{
		Name:     "api_token",
		Value:    apiToken,
		Expires:  expires,
		MaxAge:   ttl,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	w.Write([]byte("{ \"token\": \"" + apiToken + "\" }"))
}
