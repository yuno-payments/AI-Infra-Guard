// Copyright (c) 2024-2026 Tencent Zhuque Lab. All rights reserved.
// Licensed under the Apache License, Version 2.0. See auth.go header / NOTICE.
//
// yuno-payments fork: tests for the added bearer-auth middleware.

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func newRouter(token string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	g := r.Group("/api/v1")
	g.Use(BearerAuthMiddleware(token))
	g.GET("/ping", func(c *gin.Context) { c.String(http.StatusOK, "pong") })
	return r
}

func do(r *gin.Engine, auth string) int {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ping", nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code
}

func TestBearerAuth(t *testing.T) {
	cases := []struct {
		name  string
		token string
		auth  string
		want  int
	}{
		{"no token configured = passthrough", "", "", http.StatusOK},
		{"valid token", "s3cr3t", "Bearer s3cr3t", http.StatusOK},
		{"missing header", "s3cr3t", "", http.StatusUnauthorized},
		{"wrong token", "s3cr3t", "Bearer nope", http.StatusUnauthorized},
		{"missing bearer prefix", "s3cr3t", "s3cr3t", http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := do(newRouter(tc.token), tc.auth); got != tc.want {
				t.Fatalf("got %d want %d", got, tc.want)
			}
		})
	}
}
