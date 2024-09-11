package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGenerateTokens(t *testing.T) {
	guid := "12345678-1234-1234-1234-123456789012"
	ipAddress := "192.168.1.1"
	accessToken, refreshToken, err := generateTokens(guid, ipAddress)
	if err != nil {
		t.Errorf("Error generating tokens: %v", err)
	}
	if accessToken == "" || refreshToken == "" {
		t.Errorf("Access token or refresh token is empty")
	}
}

func TestHandleTokenGeneration(t *testing.T) {
	req, err := http.NewRequest("GET", "/token?guid=12345678-1234-1234-1234-123456789012", nil)
	if err != nil {
		t.Errorf("Error creating request: %v", err)
	}
	w := httptest.NewRecorder()
	handleTokenGeneration(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected status code 200, got %d", w.Code)
	}
	var response struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Errorf("Error unmarshaling response: %v", err)
	}
	if response.AccessToken == "" || response.RefreshToken == "" {
		t.Errorf("Access token or refresh token is empty")
	}
}

func TestHandleTokenRefresh(t *testing.T) {
	accessToken, refreshToken, err := generateTokens("12345678-1234-1234-1234-123456789012", "192.168.1.1")
	if err != nil {
		t.Errorf("Error generating tokens: %v", err)
	}
	req, err := http.NewRequest("GET", "/refresh?access_token="+accessToken+"&refresh_token="+refreshToken, nil)
	if err != nil {
		t.Errorf("Error creating request: %v", err)
	}
	w := httptest.NewRecorder()
	handleTokenRefresh(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected status code 200, got %d", w.Code)
	}
	var response struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Errorf("Error unmarshaling response: %v", err)
	}
	if response.AccessToken == "" || response.RefreshToken == "" {
		t.Errorf("Access token or refresh token is empty")
	}
}
