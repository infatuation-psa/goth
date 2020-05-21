// Package reddit implements the OAuth2 protocol for authenticating users through Reddit.
// This package can be used as a reference implementation of an OAuth2 provider for Reddit.
package reddit

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/ioutil"

	"github.com/infatuation-psa/goth"
	"golang.org/x/oauth2"

	"fmt"
	"net/http"
)

const (
	authURL      string = "https://www.reddit.com/api/v1/authorize"
	tokenURL     string = "https://www.reddit.com/api/v1/access_token"
	userEndpoint string = "https://www.reddit.com/api/v1/me"
)

const (
	// ScopeIdentity allows access to account information.
	ScopeIdentity = "identity"
	// ScopeEdit allows modification and deletion of comments and submissions.
	ScopeEdit = "edit"
	// ScopeFlair allows modification of user link flair on submissions.
	ScopeFlair = "flair"
	// ScopeHistory allows access to user voting history on comments and submissions
	ScopeHistory = "history"
	// ScopeModConfig allows management of configuration, sidebar, and CSS of user managed subreddits.
	ScopeModConfig = "modconfig"
	// ScopeModFlair allows management and assignment of user moderated subreddits.
	ScopeModFlair = "modflair"
	// ScopeModLog allows access to moderation log for user moderated subreddits.
	ScopeModLog = "modlog"
	// ScopeModWiki allows changing of editors and visibility of wiki pages in user moderated subreddits.
	ScopeModWiki = "modwiki"
	// ScopeMySubreddits allows access to the list of subreddits user moderates, contributes to, and is subscribed to.
	ScopeMySubreddits = "mysubreddits"
	// ScopePrivateMessages allows access to user inbox and the sending of private messages to other users.
	ScopePrivateMessages = "privatemessages"
	// ScopeRead allows access to user posts and comments.
	ScopeRead = "read"
	// ScopeReport allows reporting of content for rules violations.
	ScopeReport = "report"
	// ScopeSave allows saving and unsaving of user comments and submissions.
	ScopeSave = "save"
	// ScopeSubmit allows user submission of links and comments.
	ScopeSubmit = "submit"
	// ScopeSubscribe allows management of user subreddit subscriptions and friends.
	ScopeSubscribe = "subscribe"
	// ScopeVote allows user submission and changing of votes on comments and submissions.
	ScopeVote = "vote"
	// ScopeWikiEdit allows user editing of wiki pages.
	ScopeWikiEdit = "wikiedit"
	// ScopeWikiRead allow user viewing of wiki pages.
	ScopeWikiRead = "wikiread"
)

// New creates a new Reddit provider, and sets up important connection details.
// You should always call `reddit.New` to get a new Provider. Never try to create
// one manually.
func New(clientKey string, secret string, callbackURL string, userAgent string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		UserAgent:    userAgent,
		providerName: "reddit",
	}
	p.config = newConfig(p, scopes)
	return p
}

// Provider is the implementation of `goth.Provider` for accessing Reddit
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	UserAgent    string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
}

// Client gets the client with proper userAgent
func (p *Provider) Client(code string) *http.Client {
	if p.HTTPClient != nil {
		return p.HTTPClient
	}

	client := &http.Client{
		Transport: &oauth2.Transport{
			Source: p.config.TokenSource(oauth2.NoContext, &oauth2.Token{
				AccessToken: code,
			}),
			Base: &uaSetterTransport{
				config:    p.config,
				userAgent: p.UserAgent,
			},
		},
	}

	return client
}

// Name gets the name used to retrieve this provider.
func (p *Provider) Name() string {
	return p.providerName
}

// SetName is to update the name of the provider (needed in case of multiple providers of 1 type)
func (p *Provider) SetName(name string) {
	p.providerName = name
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
}

func (t *uaSetterTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", t.userAgent)
	// set a non-standard Authorization header because reddit demands it
	// https://github.com/reddit/reddit/wiki/OAuth2#retrieving-the-access-token
	req.Header.Set("Authorization", basicAuth(t.config.ClientID, t.config.ClientSecret))
	return http.DefaultTransport.RoundTrip(req)
}

type uaSetterTransport struct {
	config    *oauth2.Config
	userAgent string
}

// Debug is no-op for the Reddit package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Reddit for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {

	url := p.config.AuthCodeURL(state) + "&duration=permanent"

	s := &Session{
		AuthURL: url,
	}

	p.Client(s.AccessToken)

	return s, nil
}

// FetchUser will go to Reddit and access basic info about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {

	s := session.(*Session)

	user := goth.User{
		AccessToken:  s.AccessToken,
		Provider:     p.Name(),
		RefreshToken: s.RefreshToken,
		ExpiresAt:    s.ExpiresAt,
	}

	if user.AccessToken == "" {
		// data is not yet retrieved since accessToken is still empty
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	req, err := http.NewRequest("GET", userEndpoint, nil)
	if err != nil {
		return user, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.AccessToken)

	resp, err := p.Client(s.AccessToken).Do(req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return user, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch user information", p.providerName, resp.StatusCode)
	}

	bits, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return user, err
	}

	err = json.NewDecoder(bytes.NewReader(bits)).Decode(&user.RawData)
	if err != nil {
		return user, err
	}

	err = userFromReader(bytes.NewReader(bits), &user)
	if err != nil {
		return user, err
	}

	return user, err
}

func userFromReader(r io.Reader, user *goth.User) error {
	u := struct {
		Name       string `json:"display_name_prefixed"`
		Avatar     string `json:"icon_img"`
		MFAEnabled bool   `json:"mfa_enabled"`
		Verified   bool   `json:"verified"`
		ID         string `json:"id"`
	}{}

	err := json.NewDecoder(r).Decode(&u)
	if err != nil {
		return err
	}

	user.Name = u.Name
	user.AvatarURL = u.Avatar
	user.UserID = u.ID

	return nil
}

func newConfig(p *Provider, scopes []string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     p.ClientKey,
		ClientSecret: p.Secret,
		RedirectURL:  p.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
		Scopes: []string{},
	}

	if len(scopes) > 0 {
		for _, scope := range scopes {
			c.Scopes = append(c.Scopes, scope)
		}
	} else {
		c.Scopes = []string{ScopeIdentity}
	}

	return c
}

//RefreshTokenAvailable refresh token is provided by auth provider or not
func (p *Provider) RefreshTokenAvailable() bool {
	return true
}

//RefreshToken get new access token based on the refresh token
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	token := &oauth2.Token{RefreshToken: refreshToken}
	ts := p.config.TokenSource(oauth2.NoContext, token)
	newToken, err := ts.Token()
	if err != nil {
		return nil, err
	}
	return newToken, err
}
