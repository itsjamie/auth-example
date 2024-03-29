package main

import (
	"errors"
	"fmt"
	"net/http"

	"golang.org/x/crypto/bcrypt"

	"github.com/Sirupsen/logrus"
	"github.com/gorilla/mux"
)

// Data

type User struct {
	Username string
	Password string
}

// Persistance

type UserStore interface {
	Get(id string) (*User, error)
	Save(user *User, newPassword string) error
}

// MemoryUserStore is an implementation of UsersStore that using an in-memory map to store users
type MemoryUserStore struct {
	users map[string]*User
}

// Get returns a user identified by id if it exists
func (u *MemoryUserStore) Get(id string) (*User, error) {
	user, exists := u.users[id]
	if !exists {
		return nil, fmt.Errorf("user (%s) doesn't exist", id)
	}

	return user, nil
}

// Save persists the provided user into the in-memory map if the user has a username
// Also, it will overwrite the users plaintext password in memory with the hash equivalent
func (u *MemoryUserStore) Save(user *User, newPassword string) error {
	if user.Username == "" {
		return fmt.Errorf("username required")
	}

	/*
		Using an expensive hash function does enable a secondary attack that you will have to solve.
		This attack is a Denial-of-Service against your authentication servers.
		The reason why you want a cost to hashing is to slow down an attacker in a offline brute force.
		Imagine the case when your database gets leaked somehow, even with direct access to the target hash it will take the attacker
		a fair amount of time to figure out a plaintext password that generates the same hash for a user.

		We use a costly hash function so we can maintain a long enough window with offline attacks so we can:
		• notify end users of a compromise and enable a password reset for everyone on the website
		• give end users the time to change their password on websites they may have used the same password on
	*/
	if newPassword != "" {
		pass, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("error when hashing password: %s", err.Error())
		}

		// Store Hash
		user.Password = string(pass)
	}

	u.users[user.Username] = user
	return nil
}

// HTTP

// LoginHandler responds to people using HTTP who want to login
type LoginHandler struct {
	UsersStore UserStore
}

// ServeHTTP will either respond with
// • text/html representation when hit with a GET
// • handle application/x-www-form-urlencoded request body POST requests
//   if successful, login will redirect user to /secret endpoint
func (lh LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		lh.respondWithSignupForm(w, r)
	case "POST":
		lh.handleSignupFormPost(w, r)
	}
}

func (lh LoginHandler) respondWithSignupForm(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(`<html>
    <head></head>
    <body>
        <form id="login" method="POST" action="" accept-charset="utf-8">
            <input type="text" name="username" required placeholder="username" />
            <input type="password" name="password" required placeholder="password" />
            <input type="submit" name="submit" value="Login" />
        </form>
    </body>
</html>`))
}

func (lh LoginHandler) handleSignupFormPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		logrus.WithError(err).Error("failed when parsing login form")
		// Instead of a white page with an error that will output
		//  maybe we would show a pretty error page instead.
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	username := r.PostForm.Get("username")
	password := r.PostForm.Get("password")

	// Fetch Authentication from persistence
	user, err := lh.UsersStore.Get(username)
	if err != nil {
		logrus.WithError(err).Warn("invalid login attempt")
		http.Error(w, fmt.Sprintf("We couldn't find the specified user, %s.", username), http.StatusBadRequest)
		return
	}

	// Compare credentials with hashing function
	// As before, timing attacks are still possible. Internally CompareHashAndPassword uses subtle.ConstantTimeCompare to prevent timing attacks
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		logrus.WithError(errors.New("password mismatch")).Warn("invalid login attempt")
		http.Error(w, fmt.Sprintf("Incorrect password"), http.StatusBadRequest)
		return
	}

	// Successful auth!
	w.Header().Set("Location", "/secret")
	http.SetCookie(w, &http.Cookie{
		Name:  "id",
		Value: user.Username,
	})
	w.WriteHeader(http.StatusSeeOther)
}

type SecretHandler struct {
	UserStore UserStore
}

// SecretHandler will respond with a text/html representation when hit with a GET.
func (lh SecretHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("id")
	if err != nil {
		logrus.WithError(err).Error("failed to retrieve cookie \"id\"")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	user, err := lh.UserStore.Get(cookie.Value)
	if err != nil {
		logrus.WithError(err).Error("failed to retrieve user with cookie data")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	w.Write([]byte(`<html>
    <head></head>
    <body>
        <p>This is secret data for you</p>
        <ul><li>Username: ` + user.Username + `</li><li>Password Hash: ` + user.Password + `</li>
    </body>
</html>`))
}

// Start the Program

func main() {
	userStore := &MemoryUserStore{
		users: make(map[string]*User),
	}

	// ignoring errors
	userStore.Save(&User{
		Username: "jamie",
		Password: "12345",
	}, "12345")

	userStore.Save(&User{
		Username: "fixation",
		Password: "neverneeded",
	}, "neverneeded")

	r := mux.NewRouter()

	r.Handle("/login", LoginHandler{
		UsersStore: userStore,
	}).Methods("GET", "POST")

	r.Handle("/secret", SecretHandler{
		UserStore: userStore,
	}).Methods("GET")

	if err := http.ListenAndServe(":8080", r); err != nil {
		logrus.WithError(err).WithField("port", "8080").Error("failed to start HTTP server")
	}
}
