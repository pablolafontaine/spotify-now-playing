package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	refreshTimeout = 45 * time.Minute
	updateInterval = 5 * time.Second
)

var (
	mu           sync.Mutex
	currentTrack TrackInfo
	exitChan     = make(chan struct{}) // Channel to signal goroutine exit
)

type TrackInfo struct {
	ID         string `json:"id"`
	AlbumName  string `json:"album_name"`
	TrackName  string `json:"name"`
	Artists    string `json:"artists"`
	Link       string `json:"external_url"`
	IsPlaying  bool   `json:"is_playing"`
	AlbumImage string `json:"album_image"`
}

func main() {
	var err error
	var accessToken string
	accessToken, err = refreshAccessToken()
	if err != nil {
		log.Printf("Error getting access token: %v", err)

	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	go func() {
		for {
			time.Sleep(refreshTimeout)
			accessToken, err = refreshAccessToken()
			if err != nil {
				log.Printf("Error getting access token: %v", err)
			}
		}
	}()

	go func(exitChan <-chan struct{}) {
		for {
			select {
			case <-exitChan:
				return
			default:
				currentTrack, err = getCurrentTrack(accessToken)
				if err != nil {
					log.Printf("Error getting current track: %v", err)
				}
				time.Sleep(updateInterval)
			}
		}
	}(exitChan)

	http.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		if currentTrack.ID == "" {
			http.Error(w, "No track currently playing", http.StatusNotFound)
			return
		}

		// Return the currently playing track as JSON
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(currentTrack)
		if err != nil {
			log.Printf("Error encoding JSON: %v", err)
			http.Error(w, "Error encoding JSON", http.StatusInternalServerError)
			return
		}
	})

	err = http.ListenAndServe(":"+port, nil)
	if err != nil {
		log.Fatalf("Error starting the server: %v", err)
		return
	}

	close(exitChan)
}

type AccessTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

func refreshAccessToken() (string, error) {
	tokenURL := "https://accounts.spotify.com/api/token"
	refreshToken := os.Getenv("REFRESH_TOKEN")
	if refreshToken == "" {
		return "", fmt.Errorf("no refresh token given")
	}
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("error creating request: %v", err)
	}
	clientID := os.Getenv("CLIENT_ID")
	clientSecret, err := os.ReadFile(".client_secret")
	if err != nil {
		return "", fmt.Errorf("error reading client_secret")
	}
	if clientID == "" {

		return "", fmt.Errorf("$CLIENT_ID is not set")
	}
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(clientID+":"+string(clientSecret))))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error performing request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected response status: %s", resp.Status)
	}

	var tokenResponse AccessTokenResponse
	err = json.NewDecoder(resp.Body).Decode(&tokenResponse)
	if err != nil {
		return "", fmt.Errorf("error decoding JSON response: %v", err)
	}

	return tokenResponse.AccessToken, nil
}

func getCurrentTrack(accessToken string) (TrackInfo, error) {
	apiURL := "https://api.spotify.com/v1/me/player"
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return TrackInfo{}, fmt.Errorf("error creating request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return TrackInfo{}, fmt.Errorf("error performing request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return TrackInfo{}, fmt.Errorf("unexpected response status: %s", resp.Status)
	}

	var playerResponse map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&playerResponse)
	if err != nil {
		return TrackInfo{}, fmt.Errorf("error decoding JSON response: %v", err)
	}

	isPlaying, ok := playerResponse["is_playing"].(bool)
	if !ok || !isPlaying {
		return TrackInfo{}, nil
	}

	track, ok := playerResponse["item"].(map[string]interface{})
	if !ok {
		return TrackInfo{}, fmt.Errorf("no track information in the response")
	}

	artists, ok := track["artists"].([]interface{})
	if !ok {
		return TrackInfo{}, fmt.Errorf("no artist information in the response")
	}

	artistNames := make([]string, len(artists))
	for i, artist := range artists {
		artistMap, ok := artist.(map[string]interface{})
		if !ok {
			return TrackInfo{}, fmt.Errorf("invalid artist information in the response")
		}
		artistNames[i] = artistMap["name"].(string)
	}

	album, ok := track["album"].(map[string]interface{})
	if !ok {
		return TrackInfo{}, fmt.Errorf("no album information in the response")
	}

	albumName, ok := album["name"].(string)
	if !ok {
		return TrackInfo{}, fmt.Errorf("no album name in the response")
	}

	images, ok := album["images"].([]interface{})
	if !ok {
		return TrackInfo{}, fmt.Errorf("no album images in the response")
	}

	var albumImageURL string
	if len(images) > 0 {
		albumImageURL, ok = images[0].(map[string]interface{})["url"].(string)
		if !ok {
			return TrackInfo{}, fmt.Errorf("invalid album image URL in the response")
		}
	}

	return TrackInfo{
		ID:         track["id"].(string),
		TrackName:  track["name"].(string),
		Artists:    strings.Join(artistNames, ", "),
		Link:       track["external_urls"].(map[string]interface{})["spotify"].(string),
		IsPlaying:  isPlaying,
		AlbumImage: albumImageURL,
		AlbumName:  albumName,
	}, nil
}
