package main

import (
	"context"
	"log"
	"net/http"
	"strings"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"google.golang.org/api/option"
)

func publicHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("From public endpoint!"))
}

func protectedHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("From protected endpoint!"))
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.Header().Set("Access-Control-Allow-Methods", "*")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "unauthorized user", http.StatusUnauthorized)
			return
		}

		token := strings.Split(authHeader, " ")
		if len(token) != 2 || token[0] != "Bearer" {
			http.Error(w, "unauthorized user", http.StatusUnauthorized)
			return
		}

		_, err := firebaseAuth.VerifyIDToken(r.Context(), token[1])
		if err != nil {
			http.Error(w, "unauthorized user", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

var firebaseAuth *auth.Client

func main() {
	ctx := context.Background()

	opt := option.WithCredentialsFile("./firebase-sa.json")
	app, err := firebase.NewApp(ctx, nil, opt)
	if err != nil {
		log.Fatal(err)
		return
	}

	firebaseAuth, err = app.Auth(ctx)
	if err != nil {
		log.Fatal(err)
		return
	}

	http.Handle("/public", corsMiddleware(http.HandlerFunc(publicHandler)))
	http.Handle("/protected", corsMiddleware(authMiddleware(http.HandlerFunc(protectedHandler))))

	log.Fatal(http.ListenAndServe(":9000", nil))
}
