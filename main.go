package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

func generateTokens(guid string, ipAddress string) (string, string, error) {
	// Генерация токена
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"guid": guid,
		"ip":   ipAddress,
		"exp":  time.Now().Add(time.Hour * 1).Unix(), // ограничение токена на 1 час
	})
	accessToken, err := token.SignedString([]byte("secretKey"))
	if err != nil {
		return "", "", err
	}

	// Generate Refresh token
	refreshToken := fmt.Sprintf("%s:%s", guid, ipAddress)
	hash, err := bcrypt.GenerateFromPassword([]byte(refreshToken), 12)
	if err != nil {
		return "", "", err
	}
	refreshTokenBase64 := base64.StdEncoding.EncodeToString(hash)

	return accessToken, refreshTokenBase64, nil
}

func handleTokenGeneration(w http.ResponseWriter, r *http.Request) {
	guid := r.URL.Query().Get("guid")
	ipAddress := r.RemoteAddr
	accessToken, refreshToken, err := generateTokens(guid, ipAddress)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, `{"access_token": "%s", "refresh_token": "%s"}`, accessToken, refreshToken)
}

func handleTokenRefresh(w http.ResponseWriter, r *http.Request) {
	accessToken := r.URL.Query().Get("access_token")
	refreshToken := r.URL.Query().Get("refresh_token")

	// Проверка токена
	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		return []byte("secretKey"), nil
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !claims.VerifyExpiresAt(time.Now().Unix(), true) {
		http.Error(w, "Access token is invalid or expired", http.StatusUnauthorized)
		return
	}
	guid := claims["guid"].(string)
	ipAddress := claims["ip"].(string)

	hash, err := bcrypt.GenerateFromPassword([]byte(refreshToken), 12)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	refreshTokenBase64 := base64.StdEncoding.EncodeToString(hash)
	if refreshTokenBase64 != refreshToken {
		http.Error(w, "Refresh token is invalid", http.StatusUnauthorized)
		return
	}

	// Проверка IP на смену
	if ipAddress != r.RemoteAddr {
		// Отправка уведомления на почту о смене IP
		fmt.Println("IP address has changed.")
	}

	// Создание нового токена
	newAccessToken, _, err := generateTokens(guid, ipAddress)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, `{"access_token": "%s", "refresh_token": "%s"}`, newAccessToken, refreshToken)
}

func main() {
	http.HandleFunc("/token", handleTokenGeneration)
	http.HandleFunc("/refresh", handleTokenRefresh)
	fmt.Println("Server listening on port 8080")
	http.ListenAndServe(":8080", nil)
}
