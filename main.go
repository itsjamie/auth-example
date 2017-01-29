package main

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"

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
	Save(user *User) error
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
func (u *MemoryUserStore) Save(user *User) error {
	if user.Username == "" {
		return fmt.Errorf("username required")
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

	/*
	   When comparing credentials to prevent a timing attack, we need to use a constant time comparator.

	   This ensures that regardless of how dissimlar the password it, the computer will always take the same amount of time to compare them.
	   This prevents people from walking the solution space and looking for the password that takes longer to compute.

	   The reason this is a thing, is that the first step for the majority of languages with == or === equality is to check the length,
	   if they are different immediately say they can't be equal. Second, it will compare on some bit level (4 bit, 8 bit, 16 bit, 32 bit)
	   at a time, so as soon as one of those is different, it'll immediately exit.

	   As an attacker, they can take advantage of this by walking the solution space, (a, aa, aaa, aaaa, aaaaa, aaaaaa, aaaaaaa... etc) to first determine the length of the password.
	   Then, once you have determined the length, you proceed to look for the character (aaaaaaa, abaaaaa, acaaaaa, acbaaaa, etc)
	   at that length that takes the longest until you finally are granted access. A time consuming effort, but possible even across the internet.
	*/
	if subtle.ConstantTimeCompare([]byte(user.Password), []byte(password)) != 1 {
		logrus.WithError(errors.New("password mismatch")).Warn("invalid login attempt")
		http.Error(w, fmt.Sprintf("Incorrect password"), http.StatusBadRequest)
		return
	}

	// Successful auth!
	w.Header().Set("Location", "/secret")
	w.WriteHeader(http.StatusSeeOther)
}

// SecretHandler will respond with a text/html representation when hit with a GET.
func SecretHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(`<html>
    <head></head>
    <body>
        <p>This is secret data</p>
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
	})

	r := mux.NewRouter()

	r.Handle("/login", LoginHandler{
		UsersStore: userStore,
	}).Methods("GET", "POST")

	r.HandleFunc("/secret", SecretHandler).Methods("GET")

	if err := http.ListenAndServe(":8080", r); err != nil {
		logrus.WithError(err).WithField("port", "8080").Error("failed to start HTTP server")
	}
}
