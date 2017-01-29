package main

import (
	"errors"
	"fmt"
	"net/http"

	"golang.org/x/crypto/bcrypt"

	"github.com/Sirupsen/logrus"
	"github.com/davecgh/go-spew/spew"
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
// Also, it will overwrite the users plaintext password in memory with the hash equivalent
func (u *MemoryUserStore) Save(user *User) error {
	if user.Username == "" {
		return fmt.Errorf("username required")
	}

	/*
		bcrypt.DefaultCost is a constant that configures approximately how much work the computer will have to do to generate a hash.

		A good practice is to set this value so that the login path of your application takes at least 500ms to run.
		The reason for this is to makes a brute force attack take some time. This includes both an online brute force, as well as an offline brute force.

		Using an expensive hash function does enable a secondary attack that you will have to solve.
		This attack is a Denial-of-Service against your authentication servers.
		The reason why you want a cost to hashing is to slow down an attacker in a offline brute force.
		Imagine the case when your database gets leaked somehow, even with direct access to the target hash it will take the attacker
		a fair amount of time to figure out a plaintext password that generates the same hash for a user.

		At this point, you might be about to ask, can't someone precompute the output of the hashing function?

		Absolutely! The output of this technique is called rainbow tables.

		To combat this, the bcrypt hashing function automatically individually "salts" the passwords.
		So your password becomes "mypasswordsalted" before it is run through the hash function.
		A niceity of bcrypt is that it stores these salts for you in the hash, as well as the Cost that created the hash.
		The reason this is so nice, is that it enables you to rotate the hash to a higher cost as computational power gets better.

		We rotate as computational power gets better so we can maintain a long enough window so we can:
		• notify end users of a compromise and enable a password reset for everyone on the website
		• give end users the time to change their password on websites they may have used the same password on
	*/
	pass, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("error when hashing password: %s", err.Error())
	}

	// Store Hash
	user.Password = string(pass)

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

	// Showcase individual salting everytime we restart server
	spew.Dump(user)

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
