package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	maxMessageSize = 16 * 1024
	maxURLLength   = 8 * 1024
	maxLogSize     = 10 * 1024 * 1024
	rotatedLogs    = 3
)

var sensitiveParameters = map[string]struct{}{
	"access_token":  {},
	"api_key":       {},
	"apikey":        {},
	"auth":          {},
	"authorization": {},
	"code":          {},
	"key":           {},
	"password":      {},
	"session":       {},
	"session_id":    {},
	"token":         {},
}

var searchParameters = map[string]struct{}{
	"p": {}, "pq": {}, "q": {}, "query": {}, "search": {}, "text": {},
}

var searchEngineDomains = []string{"bing.com", "google.com", "duckduckgo.com", "search.yahoo.com"}

type navigationEvent struct {
	SchemaVersion        int      `json:"schema_version"`
	EventType            string   `json:"event_type"`
	EventID              string   `json:"event_id"`
	Timestamp            string   `json:"timestamp"`
	Browser              string   `json:"browser"`
	URL                  string   `json:"url"`
	URLHost              string   `json:"url_host"`
	TabID                int64    `json:"tab_id"`
	DocumentID           string   `json:"document_id,omitempty"`
	NavigationKind       string   `json:"navigation_kind"`
	TransitionType       string   `json:"transition_type"`
	TransitionQualifiers []string `json:"transition_qualifiers"`
	Source               string   `json:"source"`
}

type acknowledgement struct {
	Accepted bool   `json:"accepted"`
	EventID  string `json:"event_id,omitempty"`
	Error    string `json:"error,omitempty"`
}

func main() {
	if err := run(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "navigation host:", err)
		os.Exit(1)
	}
}

func run(input io.Reader, output io.Writer) error {
	reader := bufio.NewReader(input)
	writer := bufio.NewWriter(output)

	for {
		payload, err := readNativeMessage(reader)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}

		event, eventID, err := parseAndValidateEvent(payload)
		if err != nil {
			if writeErr := writeAcknowledgement(writer, acknowledgement{
				Accepted: false,
				EventID:  eventID,
				Error:    err.Error(),
			}); writeErr != nil {
				return writeErr
			}
			continue
		}

		if err := appendNavigationEvent(event); err != nil {
			fmt.Fprintln(os.Stderr, "navigation host: write failed:", err)
			if writeErr := writeAcknowledgement(writer, acknowledgement{
				Accepted: false,
				EventID:  event.EventID,
				Error:    "failed to persist event",
			}); writeErr != nil {
				return writeErr
			}
			continue
		}

		if err := writeAcknowledgement(writer, acknowledgement{
			Accepted: true,
			EventID:  event.EventID,
		}); err != nil {
			return err
		}
	}
}

func readNativeMessage(reader io.Reader) ([]byte, error) {
	var length uint32
	if err := binary.Read(reader, binary.LittleEndian, &length); err != nil {
		return nil, err
	}
	if length == 0 || length > maxMessageSize {
		return nil, fmt.Errorf("invalid native message length: %d", length)
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, fmt.Errorf("incomplete native message: %w", err)
	}
	return payload, nil
}

func writeAcknowledgement(writer *bufio.Writer, ack acknowledgement) error {
	payload, err := json.Marshal(ack)
	if err != nil {
		return err
	}
	if err := binary.Write(writer, binary.LittleEndian, uint32(len(payload))); err != nil {
		return err
	}
	if _, err := writer.Write(payload); err != nil {
		return err
	}
	return writer.Flush()
}

func parseAndValidateEvent(payload []byte) (navigationEvent, string, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		return navigationEvent{}, "", errors.New("message is not valid JSON")
	}

	var event navigationEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		return navigationEvent{}, extractEventID(raw), errors.New("message fields have invalid types")
	}

	if event.SchemaVersion != 1 {
		return navigationEvent{}, event.EventID, errors.New("unsupported schema_version")
	}
	if event.EventType != "browser_navigation" {
		return navigationEvent{}, event.EventID, errors.New("unsupported event_type")
	}
	if len(event.EventID) == 0 || len(event.EventID) > 128 {
		return navigationEvent{}, event.EventID, errors.New("invalid event_id")
	}
	if event.Browser != "edge" || event.Source != "edge_extension" {
		return navigationEvent{}, event.EventID, errors.New("invalid event source")
	}
	if event.TabID < 0 {
		return navigationEvent{}, event.EventID, errors.New("invalid tab_id")
	}
	if len(event.DocumentID) > 128 {
		return navigationEvent{}, event.EventID, errors.New("document_id is too long")
	}
	if event.NavigationKind != "committed" && event.NavigationKind != "history_state" {
		return navigationEvent{}, event.EventID, errors.New("invalid navigation_kind")
	}
	if len(event.TransitionType) == 0 || len(event.TransitionType) > 64 {
		return navigationEvent{}, event.EventID, errors.New("invalid transition_type")
	}
	if len(event.TransitionQualifiers) > 16 {
		return navigationEvent{}, event.EventID, errors.New("too many transition_qualifiers")
	}
	for _, qualifier := range event.TransitionQualifiers {
		if len(qualifier) == 0 || len(qualifier) > 64 {
			return navigationEvent{}, event.EventID, errors.New("invalid transition_qualifier")
		}
	}

	timestamp, err := time.Parse(time.RFC3339Nano, event.Timestamp)
	if err != nil {
		return navigationEvent{}, event.EventID, errors.New("invalid timestamp")
	}
	event.Timestamp = timestamp.UTC().Format(time.RFC3339Nano)

	normalizedURL, normalizedHost, err := normalizeURL(event.URL)
	if err != nil {
		return navigationEvent{}, event.EventID, err
	}
	if event.URLHost != "" && !strings.EqualFold(event.URLHost, normalizedHost) {
		return navigationEvent{}, event.EventID, errors.New("url_host does not match URL")
	}
	event.URL = normalizedURL
	event.URLHost = normalizedHost

	return event, event.EventID, nil
}

func extractEventID(raw map[string]json.RawMessage) string {
	var eventID string
	_ = json.Unmarshal(raw["event_id"], &eventID)
	return eventID
}

func normalizeURL(raw string) (string, string, error) {
	if len(raw) == 0 || len(raw) > maxURLLength {
		return "", "", errors.New("invalid URL length")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" {
		return "", "", errors.New("invalid URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", "", errors.New("unsupported URL scheme")
	}

	parsed.User = nil
	parsed.Fragment = ""
	hostname := strings.ToLower(parsed.Hostname())
	query := parsed.Query()
	for key := range query {
		normalizedKey := strings.ToLower(key)
		_, sensitive := sensitiveParameters[normalizedKey]
		_, searchTerm := searchParameters[normalizedKey]
		if sensitive || (searchTerm && isSearchEngineHost(hostname)) {
			query[key] = []string{"[REDACTED]"}
		}
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), hostname, nil
}

func isSearchEngineHost(hostname string) bool {
	for _, domain := range searchEngineDomains {
		if hostname == domain || strings.HasSuffix(hostname, "."+domain) {
			return true
		}
	}
	return false
}

func appendNavigationEvent(event navigationEvent) error {
	path := navigationLogPath()
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}

	release, err := acquireFileLock(path+".lock", 2*time.Second)
	if err != nil {
		return err
	}
	defer release()

	if err := rotateIfNeeded(path); err != nil {
		return err
	}

	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	payload = append(payload, '\n')

	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return err
	}
	if _, err := file.Write(payload); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func navigationLogPath() string {
	if configured := os.Getenv("PHISHING_DETECTION_LOG_FILE"); configured != "" {
		return configured
	}
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "PhishingDetection", "browser-navigation.json")
}

func acquireFileLock(path string, timeout time.Duration) (func(), error) {
	deadline := time.Now().Add(timeout)
	for {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			_ = file.Close()
			return func() { _ = os.Remove(path) }, nil
		}
		if !os.IsExist(err) {
			return nil, err
		}

		if info, statErr := os.Stat(path); statErr == nil && time.Since(info.ModTime()) > 30*time.Second {
			_ = os.Remove(path)
			continue
		}
		if time.Now().After(deadline) {
			return nil, errors.New("timed out waiting for navigation log lock")
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func rotateIfNeeded(path string) error {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Size() < maxLogSize {
		return nil
	}

	oldest := fmt.Sprintf("%s.%d", path, rotatedLogs)
	_ = os.Remove(oldest)
	for index := rotatedLogs - 1; index >= 1; index-- {
		from := fmt.Sprintf("%s.%d", path, index)
		to := fmt.Sprintf("%s.%d", path, index+1)
		if err := os.Rename(from, to); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return os.Rename(path, path+".1")
}
