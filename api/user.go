package user

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/dgrijalva/jwt-go"
	"github.com/jacob-ebey/magic/admin"
)

// Handler is the main entrypoint for the route "api/user"
func Handler(w http.ResponseWriter, r *http.Request) {
	// Only allow post requests
	if r.Method != http.MethodGet {
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

	user, err := magic.GetMetadataByIssuer(claims["issuer"].(string))
	if err != nil {
		http.Error(w, "{ \"error\": \"Could not get metadata for user\" }", http.StatusForbidden)
		return
	}

	userJson, err := json.Marshal(user)
	if err != nil {
		http.Error(w, "{ \"error\": \"Could not encode response\" }", http.StatusInternalServerError)
		return
	}

	w.Write(userJson)
}
