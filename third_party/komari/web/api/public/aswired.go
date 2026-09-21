package public

import (
	"github.com/gin-gonic/gin"
	"github.com/komari-monitor/komari/pkg/aswired"
	"net/http"
	"time"
)

func ASWiredOptions(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.JSON(200, gin.H{"enabled": aswired.Enabled(), "loginUrl": aswired.LoginURL()})
}
func ASWiredSession(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("Referrer-Policy", "no-referrer")
	if !aswired.Enabled() || aswired.Validate() != nil {
		c.AbortWithStatus(503)
		return
	}
	if c.GetHeader("Origin") != aswired.Origin() {
		c.AbortWithStatus(403)
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 4096)
	if err := c.Request.ParseForm(); err != nil {
		c.AbortWithStatus(400)
		return
	}
	ticket := c.Request.PostForm.Get("ticket")
	if len(ticket) < 32 || len(ticket) > 256 {
		c.AbortWithStatus(400)
		return
	}
	identity, err := aswired.Call(c.Request.Context(), "redeem", map[string]string{"ticket": ticket})
	if err != nil {
		c.Redirect(http.StatusSeeOther, aswired.LoginURL())
		return
	}
	maxAge := int(time.Until(identity.ExpiresAt).Seconds())
	if identity.Session == "" || maxAge <= 0 {
		c.AbortWithStatus(502)
		return
	}
	http.SetCookie(c.Writer, &http.Cookie{Name: "session_token", Value: identity.Session, Path: "/", HttpOnly: true, Secure: aswired.Secure(), SameSite: http.SameSiteLaxMode, MaxAge: maxAge, Expires: identity.ExpiresAt})
	c.Redirect(http.StatusSeeOther, "/admin")
}
