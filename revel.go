package sessions

import (
	"errors"
	"hash"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	sso "github.com/three-plus-three/sso/client"

	"github.com/revel/revel"
)

var CookiePath string

func GetValues(c *revel.Controller, sessionKey string, h func() hash.Hash, secretKey []byte) (url.Values, error) {
	cookie, err := c.Request.Cookie(sessionKey)
	if err != nil {
		if err == http.ErrNoCookie {
			return nil, errors.New("session cookie isn't found")
		}
		return nil, err
	}

	return sso.GetValuesFromString(cookie.GetValue(), func(data, sig string) bool {
		if secretKey == nil {
			return true
		}
		return sso.Verify(data, sig, h, secretKey)
	})
}

// restoreSession returns either the current session, retrieved from the
// session cookie, or a new session.
func restoreSession(c *revel.Controller, sessionKey string, h func() hash.Hash, secretKey []byte) revel.Session {
	values, err := GetValues(c, sessionKey, h, secretKey)
	if err != nil {
		revel.WARN.Println("Session cookie is read fail, ", err)
		return make(revel.Session)
	}

	session := make(revel.Session)
	for key, value := range values {
		if len(value) > 0 {
			session[key] = value[len(value)-1]
		}
	}
	return session
}

// Cookie returns an http.Cookie containing the signed session.
func getCookie(s revel.Session, sessionKey string, cookiePath string, h func() hash.Hash, secretKey []byte) *http.Cookie {
	values := url.Values{}
	for key, value := range s {
		values.Set(key, value)
	}
	ts := time.Now().Add(30 * time.Minute)
	values.Set(sso.SESSION_EXPIRE_KEY,
		strconv.FormatInt(ts.Unix(), 10))
	values.Set("_TS",
		strconv.FormatInt(ts.Unix(), 10))
	sessionData := values.Encode()

	return &http.Cookie{
		Name:  sessionKey,
		Value: sso.Sign(sessionData, h, secretKey) + "-" + sessionData,
		//Domain:   revel.CookieDomain,
		Path: cookiePath,
		//HttpOnly: true,
		//Secure:   revel.CookieSecure,
		// Expires: ts.UTC(), // 不指定过期时间，那么关闭浏览器后 cookie 会删除
	}
}

// SessionFilter is a Revel Filter that retrieves and sets the session cookie.
// Within Revel, it is available as a Session attribute on Controller instances.
// The name of the Session cookie is set as CookiePrefix + "_SESSION".
func SessionFilter(sessionKey string, cookiePath string, h func() hash.Hash, secretKey []byte) revel.Filter {
	if cookiePath == "" {
		cookiePath = "/"
	} else if !strings.HasPrefix(cookiePath, "/") {
		cookiePath = "/" + cookiePath
	}

	return func(c *revel.Controller, fc []revel.Filter) {
		c.Session = restoreSession(c, sessionKey, h, secretKey)
		sessionWasEmpty := len(c.Session) == 0

		// Make session vars available in templates as {{.session.xyz}}
		c.ViewArgs["session"] = c.Session

		fc[0](c, fc[1:])

		// Store the signed session if it could have changed.
		if len(c.Session) > 0 || !sessionWasEmpty {
			c.SetCookie(getCookie(c.Session, sessionKey, cookiePath, h, secretKey))
		}
	}
}
