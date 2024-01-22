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

	"github.com/gorilla/websocket"
	"github.com/iancoleman/orderedmap"
	"github.com/rs/cors"
)

const (
	refreshTimeout = 45 * time.Minute
	updateInterval = time.Second
)

var (
	mu            sync.Mutex
	currentTrack  TrackInfo
	previousTrack TrackInfo
	exitChan      = make(chan struct{})
	connections   = make(map[*websocket.Conn]struct{})
	upgrader      = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
)

type TrackInfo struct {
	ID         string                 `json:"id"`
	AlbumName  string                 `json:"album_name"`
	TrackName  string                 `json:"name"`
	Artists    *orderedmap.OrderedMap `json:"artists"`
	Link       string                 `json:"song_url"`
	IsPlaying  bool                   `json:"is_playing"`
	AlbumImage string                 `json:"album_image"`
	AlbumURL   string                 `json:"album_url"`
	Duration   int                    `json:"duration"`
	Progress   int                    `json:"progress"`
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
				if len(connections) > 0 {
					currentTrack, err = getCurrentTrack(accessToken)
					if err != nil {
						log.Printf("Error getting current track: %v", err)
					}

					if currentTrack.ID != previousTrack.ID {
						previousTrack = currentTrack

						broadcastTrack(currentTrack)
					}

					time.Sleep(updateInterval)
				}
			}
		}
	}(exitChan)
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}

		mu.Lock()
		connections[conn] = struct{}{}
		mu.Unlock()
		currentTrack, err = getCurrentTrack(accessToken)
		if err != nil {
			log.Fatalf("failed to get current track!")
		}
		if currentTrack.ID != previousTrack.ID {
			previousTrack = currentTrack
		}

		sendTrack(conn, currentTrack)

		<-exitChan
	})
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://pablolafontaine.com"},
		AllowCredentials: false,
		Debug:            false,
	})
	handler := c.Handler(mux)
	err = http.ListenAndServe(":"+port, handler)
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

	artistMap := orderedmap.New()
	for _, artist := range artists {
		artistInfo, ok := artist.(map[string]interface{})
		if !ok {
			return TrackInfo{}, fmt.Errorf("invalid artist information in the response")
		}
		name := artistInfo["name"].(string)
		externalURL, ok := artistInfo["external_urls"].(map[string]interface{})["spotify"].(string)
		if !ok {
			return TrackInfo{}, fmt.Errorf("no external URL for artist %s in the response", name)
		}
		artistMap.Set(name, externalURL)
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

	progress, ok := playerResponse["progress_ms"]
	if !ok {
		return TrackInfo{}, fmt.Errorf("no progress_ms in the response")
	}

	duration, ok := track["duration_ms"]
	if !ok {
		return TrackInfo{}, fmt.Errorf("no duration_ms in the response")
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
		Artists:    artistMap,
		Link:       track["external_urls"].(map[string]interface{})["spotify"].(string),
		IsPlaying:  isPlaying,
		AlbumImage: albumImageURL,
		AlbumName:  albumName,
		AlbumURL:   album["external_urls"].(map[string]interface{})["spotify"].(string),
		Duration:   int(duration.(float64)),
		Progress:   int(progress.(float64)),
	}, nil
}

func broadcastTrack(track TrackInfo) {
	mu.Lock()
	defer mu.Unlock()

	messageJSON, err := json.Marshal(track)
	if err != nil {
		log.Printf("Error encoding WebSocket message: %v", err)
		return
	}

	for conn := range connections {
		err := conn.WriteMessage(websocket.TextMessage, messageJSON)
		if err != nil {
			delete(connections, conn)
			conn.Close()
		}
	}
}

func sendTrack(conn *websocket.Conn, track TrackInfo) {
	mu.Lock()
	defer mu.Unlock()

	trackJSON, err := json.Marshal(track)
	if err != nil {
		log.Printf("Error encoding JSON: %v", err)
		return
	}

	err = conn.WriteMessage(websocket.TextMessage, trackJSON)
	if err != nil {
		delete(connections, conn)
		conn.Close()
		return
	}
}
