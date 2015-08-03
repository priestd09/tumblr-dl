package main

import (
	"encoding/json"
	"fmt"
	"github.com/garyburd/go-oauth/examples/session"
	"github.com/garyburd/go-oauth/oauth"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	//"os"
	//"path"
	"strconv"
	"text/template"
	"time"
	"archive/zip"
	//"strings"
	"path"
)

// Session state keys.
const (
	tempCredKey  = "tempCred"
	tokenCredKey = "tokenCred"
)

var oauthClient = oauth.Client{
	TemporaryCredentialRequestURI: "http://www.tumblr.com/oauth/request_token",
	ResourceOwnerAuthorizationURI: "http://www.tumblr.com/oauth/authorize",
	TokenRequestURI:               "http://www.tumblr.com/oauth/access_token",
}

// authHandler reads the auth cookie and invokes a handler with the result.
type authHandler struct {
	handler  func(w http.ResponseWriter, r *http.Request, c *oauth.Credentials)
	optional bool
}

func (h *authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cred, _ := session.Get(r)[tokenCredKey].(*oauth.Credentials)
	if cred == nil && !h.optional {
		http.Error(w, "Not logged in.", 403)
		return
	}
	h.handler(w, r, cred)
}

func readCredentials() error {
	b, err := ioutil.ReadFile("config.json")
	if err != nil {
		return err
	}
	return json.Unmarshal(b, &oauthClient.Credentials)
}

func serveHome(w http.ResponseWriter, r *http.Request, cred *oauth.Credentials) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if cred == nil {
		respond(w, homeLoggedOutTmpl, nil)
	} else {
		respond(w, homeTmpl, nil)
	}
}

func serveAuthorize(w http.ResponseWriter, r *http.Request) {
	callback := "http://" + r.Host + "/callback"
	tempCred, err := oauthClient.RequestTemporaryCredentials(nil, callback, nil)
	if err != nil {
		http.Error(w, "Error getting temp cred, "+err.Error(), 500)
		return
	}
	s := session.Get(r)
	s[tempCredKey] = tempCred
	if err := session.Save(w, r, s); err != nil {
		http.Error(w, "Error saving session , "+err.Error(), 500)
		return
	}
	http.Redirect(w, r, oauthClient.AuthorizationURL(tempCred, nil), 302)
}

// serveOAuthCallback handles callbacks from the OAuth server.
func serveOAuthCallback(w http.ResponseWriter, r *http.Request) {
	s := session.Get(r)
	tempCred, _ := s[tempCredKey].(*oauth.Credentials)
	if tempCred == nil || tempCred.Token != r.FormValue("oauth_token") {
		http.Error(w, "Unknown oauth_token.", 500)
		return
	}
	tokenCred, _, err := oauthClient.RequestToken(nil, tempCred, r.FormValue("oauth_verifier"))
	if err != nil {
		http.Error(w, "Error getting request token, "+err.Error(), 500)
		return
	}
	delete(s, tempCredKey)
	s[tokenCredKey] = tokenCred
	if err := session.Save(w, r, s); err != nil {
		http.Error(w, "Error saving session , "+err.Error(), 500)
		return
	}
	http.Redirect(w, r, "/", 302)
}

func serveLogout(w http.ResponseWriter, r *http.Request) {
	s := session.Get(r)
	delete(s, tokenCredKey)
	if err := session.Save(w, r, s); err != nil {
		http.Error(w, "Error saving session , "+err.Error(), 500)
		return
	}
	http.Redirect(w, r, "/", 302)
}

func apiGet(cred *oauth.Credentials, urlStr string, form url.Values) (*http.Response, error) {
	return oauthClient.Get(nil, cred, urlStr, form)
}

func decodeResponse(resp *http.Response, data interface{}) error {
	if resp.StatusCode != 200 {
		p, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("get %s returned status %d, %s", resp.Request.URL, resp.StatusCode, p)
	}
	return json.NewDecoder(resp.Body).Decode(data)

}

func respond(w http.ResponseWriter, t *template.Template, data interface{}) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.Execute(w, data); err != nil {
		log.Print(err)
	}
}

func getAllLikes(w http.ResponseWriter, r *http.Request, cred *oauth.Credentials) []Likes {
	var info Likes = getLikes(w, r, cred, 0)
	totalLikes := info.Response.LikedCount
	l := make([]Likes, totalLikes)
	offset := 0
	for offset <= totalLikes {
		l = append(l, getLikes(w, r, cred, offset))
		offset = offset + 20
	}
	return l
}

func getLikes(w http.ResponseWriter, r *http.Request, cred *oauth.Credentials, offset int) Likes {
	var likes Likes

	query := url.Values{}
	query.Set("limit", "20")
	query.Set("offset", strconv.Itoa(offset))

	if resp, err := apiGet(
		cred,
		"http://api.tumblr.com/v2/user/likes",
		query); err != nil {
		http.Error(w, "Error getting likes, "+err.Error(), 500)
	} else if err := decodeResponse(resp, &likes); err != nil {
		http.Error(w, "Error getting likes, "+err.Error(), 500)
	}

	return likes
}

func serveLikesDownload(w http.ResponseWriter, r *http.Request, cred *oauth.Credentials) {

	zipfilename := fmt.Sprintf("tumblr-%d.zip", uint16(time.Now().UnixNano()))

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", zipfilename))
	w.Header().Set("Connection", "close")

	zw := zip.NewWriter(w);

	likes := getAllLikes(w, r, cred)

	for _, like := range likes {
		for _, posts := range like.Response.LikedPosts {

			postId := strconv.FormatInt(posts.ID, 10)
			header := &zip.FileHeader{
				Name:         postId + " /post.txt",
				Method:       zip.Store,
				ModifiedTime: uint16(time.Now().UnixNano()),
				ModifiedDate: uint16(time.Now().UnixNano()),
			}

			fw, err := zw.CreateHeader(header)

			if err != nil {
				log.Printf("%s", err.Error())
				http.Error(w, "Internal server error.", 500)
				return
			}
			strconv.FormatInt(posts.ID, 10)
			io.WriteString(fw, posts.PostURL)

			for _, photos := range posts.Photos {
				url := photos.OriginalSize.URL
				_, fileName := path.Split(url)

				header := &zip.FileHeader{
					Name:         postId + "/" + fileName,
					Method:       zip.Store,
					ModifiedTime: uint16(time.Now().UnixNano()),
					ModifiedDate: uint16(time.Now().UnixNano()),
				}

				fw, err := zw.CreateHeader(header)

				if err != nil {
					log.Printf("%s", err.Error())
					http.Error(w, "Internal server error.", 500)
					return
				}

				resp, _ := http.Get(photos.OriginalSize.URL)

				io.Copy(fw, resp.Body)
				defer resp.Body.Close()
			}
		}
	}

	if err := zw.Close(); err != nil {
		log.Printf("%s", err.Error())
		http.Error(w, "Internal server error.", 500)
		return
	}

}

func serveLikes(w http.ResponseWriter, r *http.Request, cred *oauth.Credentials) {
	respond(w, likesTmpl, getAllLikes(w, r, cred))
}

func main() {
	println("Starting on port 9123")
	if err := readCredentials(); err != nil {
		log.Fatalf("Error reading configuration. %v", err)
	}

	if len(oauthClient.Credentials.Secret) < 16 || len(oauthClient.Credentials.Token) < 16 {
		log.Fatalf("Error reading configuration. %v", "Secret or Token too short")
	}

	http.Handle("/", &authHandler{handler: serveHome, optional: true})
	http.Handle("/likes", &authHandler{handler: serveLikes})
	http.Handle("/likes/download", &authHandler{handler: serveLikesDownload})
	http.HandleFunc("/authorize", serveAuthorize)
	http.HandleFunc("/logout", serveLogout)
	http.HandleFunc("/callback", serveOAuthCallback)
	if err := http.ListenAndServe(":9123", nil); err != nil {
		log.Fatalf("Error listening, %v", err)
	}
}

var (
	homeLoggedOutTmpl = template.Must(template.New("loggedout").Parse(
		`<html>
<head>
</head>
<body>
<a href="/authorize">Authorize</a>
</body>
</html>`))

	homeTmpl = template.Must(template.New("home").Parse(
		`<html>
<head>
</head>
<body>
<p><a href="/likes">Likes</a>
<p><a href="/logout">logout</a>
</body></html>`))

	likesTmpl = template.Must(template.New("likestemplate").Parse(
		`<html>
<head>
</head>
<body>
<p><a href="/likes/download">Download all photos</a></p>

{{range .}}
	{{range .Response.LikedPosts}}
		<p>{{.PostURL}}</p>
		{{range .Photos}}
			{{$url := index .AltSizes 4}}
			<img src="{{$url.URL}}">
		{{end}}
		<br>
	{{end}}
{{end}}
{{.}}
</p>
</body></html>`))
)

type Likes struct {
	Meta struct {
		Status int    `json:"status"`
		Msg    string `json:"msg"`
	} `json:"meta"`
	Response struct {
		LikedPosts []struct {
			ID      int64  `json:"id"`
			PostURL string `json:"post_url"`
			Photos  []struct {
				Caption      string `json:"caption"`
				OriginalSize struct {
					Width  int    `json:"width"`
					Height int    `json:"height"`
					URL    string `json:"url"`
				} `json:"original_size"`
				AltSizes []struct {
					Width  int    `json:"width"`
					Height int    `json:"height"`
					URL    string `json:"url"`
				} `json:"alt_sizes"`
			} `json:"photos"`
			LikedTimestamp int64 `json:"liked_timestamp"`
		} `json:"liked_posts"`
		LikedCount int `json:"liked_count"`
	} `json:"response"`
}
