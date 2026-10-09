// Copyright (c) 2024-2026 Tencent Zhuque Lab. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Requirement: Any integration or derivative work must explicitly attribute
// Tencent Zhuque Lab (https://github.com/Tencent/AI-Infra-Guard) in its
// documentation or user interface, as detailed in the NOTICE file.
//
// NOTE (yuno-payments fork): bearer-token authentication added so the service
// can be driven by the Pentest-as-a-Service worker over an internal network.
// Upstream A.I.G ships without any authentication mechanism.

package middleware

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// BearerAuthMiddleware returns a gin middleware that requires every request to
// carry an `Authorization: Bearer <token>` header matching the configured
// token. The comparison is constant-time to avoid leaking the token via timing.
//
// If token is empty the middleware is a no-op passthrough, preserving the
// upstream (unauthenticated) behaviour for local/standalone use. Enable auth by
// setting AIG_AUTH_TOKEN in the environment.
func BearerAuthMiddleware(token string) gin.HandlerFunc {
	expected := []byte("Bearer " + token)

	return func(c *gin.Context) {
		if token == "" {
			c.Next()
			return
		}

		got := strings.TrimSpace(c.GetHeader("Authorization"))
		if subtle.ConstantTimeCompare([]byte(got), expected) != 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"status":  1,
				"message": "unauthorized",
				"data":    nil,
			})
			return
		}

		c.Next()
	}
}
