package main

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"systems/helper"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/pborman/getopt/v2"
)

type Stats struct {
	AverageEncoding float64
	AverageDecoding float64
}

var (
	privateKey         *rsa.PrivateKey
	publicKey          *rsa.PublicKey
	publicKeyBytes     []byte
	readme             string
	privateKeyFileName string              = "private.pem"
	privateKeyPassword string              = "password"
	publicKeyFileName  string              = "public.pem"
	statistics         map[string](*Stats) = make(map[string](*Stats))
)

func authHandler(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")
	claims := &jwt.StandardClaims{
		ExpiresAt: time.Now().AddDate(0, 0, 1).Local().Unix(), // expires 1 day after now
		Subject:   username,
	}

	start := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("there was an error signing the JWT token"))
		return
	}
	duration := time.Since(start)
	userStats, ok := statistics[username]
	if ok {
		statistics[username].AverageEncoding = (userStats.AverageEncoding + duration.Seconds()) / 2
	} else {
		statistics[username] = &Stats{duration.Seconds(), 0}
	}

	cookie := http.Cookie{
		Name:     "token",
		Value:    tokenString,
		MaxAge:   86400,
		HttpOnly: true, // cookie should not be accessible by client-side JavaScript
		Path:     "/",  // cookie should be visible to all paths on the server
	}
	http.SetCookie(w, &cookie)

	w.WriteHeader(http.StatusOK)
	w.Write(publicKeyBytes)
}

func verifyHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("cookie is not present on request"))
		return
	}

	start := time.Now()
	token, err := jwt.ParseWithClaims(cookie.Value, &jwt.StandardClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("wrong signing method (should be RSA)")
		}
		return publicKey, nil
	})
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(err.Error()))
		return
	}
	duration := time.Since(start)

	if claims, ok := token.Claims.(*jwt.StandardClaims); ok && token.Valid {
		userStats, ok := statistics[claims.Subject]
		if ok {
			statistics[claims.Subject].AverageDecoding = (userStats.AverageDecoding + duration.Seconds()) / 2
		} else {
			statistics[claims.Subject] = &Stats{0, duration.Seconds()}
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(claims.Subject))
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("token is not valid"))
	}
}

func readmeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, readme)
}

func statsHandler(w http.ResponseWriter, r *http.Request) {
	output, err := json.MarshalIndent(statistics, "", "  ")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("unable to parse statistics into JSON"))
	} else {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		w.Write(output)
	}
}

func main() {
	var err error
	privateKey, publicKey, publicKeyBytes, err = helper.Keys(privateKeyFileName, privateKeyPassword, publicKeyFileName)
	if err != nil {
		fmt.Println(err)
		return
	}

	readmeBytes, err := os.ReadFile("README.md")
	if err != nil {
		fmt.Println(err)
		return
	}
	readme = string(readmeBytes)

	port := getopt.IntLong("port", 'p', 8080, "server port")
	getopt.Parse()

	router := chi.NewRouter()
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)
	router.Get("/auth/{username}", authHandler)
	router.Get("/verify", verifyHandler)
	router.Get("/README.txt", readmeHandler)
	router.Get("/stats", statsHandler)
	http.ListenAndServe(fmt.Sprintf(":%d", *port), router)
}
