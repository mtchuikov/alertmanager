// Copyright The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dion

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	commoncfg "github.com/prometheus/common/config"

	"github.com/google/uuid"
	"github.com/prometheus/alertmanager/config"
	"github.com/prometheus/alertmanager/notify"
	"github.com/prometheus/alertmanager/template"
	"github.com/prometheus/alertmanager/types"
)

// Telegram supports 4096 chars max - from https://faq.dion.vc/ru/users/chat/chatbots
const maxMessageLenRunes = 4096

type Notifier struct {
	conf    *config.DionConfig
	tmpl    *template.Template
	logger  *slog.Logger
	client  *http.Client
	retrier *notify.Retrier

	tokenMu     sync.Mutex
	cachedToken string
	tokenExpiry time.Time
}

func New(conf *config.DionConfig, t *template.Template, l *slog.Logger, httpOpts ...commoncfg.HTTPClientOption) (*Notifier, error) {
	client, err := notify.NewClientWithTracing(*conf.HTTPConfig, "dion", httpOpts...)
	if err != nil {
		return nil, err
	}

	return &Notifier{
		conf:    conf,
		tmpl:    t,
		logger:  l,
		client:  client,
		retrier: &notify.Retrier{},
	}, nil
}

func (n *Notifier) Notify(ctx context.Context, alert ...*types.Alert) (bool, error) {
	key, ok := notify.GroupKey(ctx)
	if !ok {
		return false, fmt.Errorf("group key missing")
	}

	logger := n.logger.With("group_key", key)
	logger.Debug("extracted group key")

	var (
		err         error
		data        = notify.GetTemplateData(ctx, n.tmpl, alert, logger)
		tmpl        = notify.TmplText(n.tmpl, data, &err)
		messageText string
		truncated   bool
	)

	switch n.conf.ParseMode {
	case "HTML":
		tmpl = notify.TmplHTML(n.tmpl, data, &err)
		messageText = tmpl(n.conf.Message)
		if err != nil {
			return false, err
		}

		if len([]rune(messageText)) > maxMessageLenRunes {
			messageText = `Alertmanager notification could not be sent: message length exceeds Dion limits.
			Please check the template used for producing the message content.`
		}
	default:
		messageText, truncated = notify.TruncateInRunes(tmpl(n.conf.Message), maxMessageLenRunes)
		if err != nil {
			return false, err
		}

		if truncated {
			logger.Warn("Truncated message", "max_runes", maxMessageLenRunes)
		}
	}

	chatID, err := n.getChatID()
	if err != nil {
		return false, err
	}
	chatIDStr := chatID.String()

	for attempt := range 2 {
		token, err := n.getValidToken(ctx)
		if err != nil {
			return false, err
		}

		resp, sendErr := n.sendMessage(ctx, token, chatIDStr, messageText)
		if sendErr != nil {
			return true, notify.RedactURL(sendErr)
		}

		bodyBytes, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			return true, fmt.Errorf("failed to read response body: %w", readErr)
		}

		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			n.invalidateToken()
			continue
		}

		if resp.StatusCode == http.StatusOK {
			var sr sendMessageResponse
			if jsonErr := json.Unmarshal(bodyBytes, &sr); jsonErr == nil && sr.OK {
				logger.Debug("Dion message successfully published", "message_id", sr.Result.MessageID, "chat_id", sr.Result.Chat.ID)
			}
		}

		shouldRetry, checkErr := n.retrier.Check(resp.StatusCode, bytes.NewReader(bodyBytes))
		if checkErr != nil {
			return shouldRetry, notify.NewErrorWithReason(notify.GetFailureReasonFromStatusCode(resp.StatusCode), checkErr)
		}

		return shouldRetry, checkErr
	}

	return false, nil
}

func (n *Notifier) getCredentials() (email, password string, err error) {
	if len(n.conf.BotEmailFile) > 0 {
		content, err := os.ReadFile(n.conf.BotEmailFile)
		if err != nil {
			return "", "", fmt.Errorf("could not read %s: %w", n.conf.BotEmailFile, err)
		}

		email = strings.TrimSpace(string(content))

	} else {
		email = string(n.conf.BotEmail)
	}

	if len(n.conf.BotPasswordFile) > 0 {
		content, err := os.ReadFile(n.conf.BotPasswordFile)
		if err != nil {
			return "", "", fmt.Errorf("could not read %s: %w", n.conf.BotPasswordFile, err)
		}
		password = strings.TrimSpace(string(content))
	} else {
		password = string(n.conf.BotPassword)
	}

	return email, password, nil
}

func (n *Notifier) doLogin(ctx context.Context, email, password string) (string, error) {
	tokenURL := n.conf.APIURL.String() + "/platform/v1/token"

	type loginRequest struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	body, err := json.Marshal(loginRequest{
		Email:    email,
		Password: password,
	})

	if err != nil {
		return "", fmt.Errorf("failed to marshal dion login request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create dion login request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to dion get token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to get dion token: status %d body: %s", resp.StatusCode, string(bodyBytes))
	}

	type tokenResponse struct {
		AccessToken string `json:"access_token"`
	}

	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("failed to decode dion token response: %w", err)
	}

	if tr.AccessToken == "" {
		return "", fmt.Errorf("empty dion access_token in response")
	}

	return tr.AccessToken, nil
}

func extractExpiryFromJWT(token string) (time.Time, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, fmt.Errorf("invalid JWT format")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	var claims struct {
		Exp int64 `json:"exp"`
	}

	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return time.Time{}, fmt.Errorf("failed to unmarshal JWT claims: %w", err)
	}

	if claims.Exp == 0 {
		return time.Time{}, fmt.Errorf("no 'exp' claim in JWT")
	}

	return time.Unix(claims.Exp, 0), nil
}

func (n *Notifier) fetchNewToken(ctx context.Context) (string, time.Time, error) {
	email, password, err := n.getCredentials()
	if err != nil {
		return "", time.Time{}, err
	}

	token, err := n.doLogin(ctx, email, password)
	if err != nil {
		return "", time.Time{}, err
	}

	expiry, parseErr := extractExpiryFromJWT(token)
	if parseErr != nil {
		n.logger.Warn("could not extract dion token expiry from JWT, falling back to 12h", "error", parseErr)
		expiry = time.Now().Add(11*time.Hour + 30*time.Minute)
	}

	return token, expiry, nil
}

func (n *Notifier) getValidToken(ctx context.Context) (string, error) {
	n.tokenMu.Lock()
	defer n.tokenMu.Unlock()

	if n.cachedToken != "" && time.Now().Before(n.tokenExpiry) {
		return n.cachedToken, nil
	}

	token, expiry, err := n.fetchNewToken(ctx)
	if err != nil {
		return "", err
	}

	n.cachedToken = token
	n.tokenExpiry = expiry

	return token, nil
}

func (n *Notifier) invalidateToken() {
	n.tokenMu.Lock()
	n.cachedToken = ""
	n.tokenMu.Unlock()
}

type sendMessageResponse struct {
	OK     bool `json:"ok"`
	Result struct {
		MessageID string `json:"message_id"`
		Chat      struct {
			ID string `json:"id"`
		} `json:"chat"`
	} `json:"result"`
}

func (n *Notifier) sendMessage(ctx context.Context, token, chatIDStr, text string) (*http.Response, error) {
	sendURL := n.conf.APIURL.String() + "/chats/v2/sendMessage"

	payload := map[string]string{
		"chat_id": chatIDStr,
		"text":    text,
	}
	if n.conf.ParseMode != "" {
		payload["parse_mode"] = n.conf.ParseMode
	} else {
		payload["parse_mode"] = "Markdown"
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(payload); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sendURL, &buf)
	if err != nil {
		return nil, fmt.Errorf("failed to create send request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := n.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send message: %w", err)
	}

	return resp, nil
}

func (n *Notifier) getChatID() (uuid.UUID, error) {
	if len(n.conf.ChatIDFile) > 0 {
		content, err := os.ReadFile(n.conf.ChatIDFile)
		if err != nil {
			return uuid.Nil, fmt.Errorf("could not read %s: %w", n.conf.ChatIDFile, err)
		}

		chatID, err := uuid.ParseBytes(content)
		if err != nil {
			return uuid.Nil, fmt.Errorf("could not parse chat_id from %s: %w", n.conf.ChatIDFile, err)
		}

		return chatID, nil
	}

	return n.conf.ChatID, nil
}
