package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func validEvent() navigationEvent {
	return navigationEvent{
		SchemaVersion:        1,
		EventType:            "browser_navigation",
		EventID:              "event-1",
		Timestamp:            "2026-07-10T08:14:22.491Z",
		Browser:              "edge",
		URL:                  "https://example.test/login?token=secret#private",
		TabID:                42,
		DocumentID:           "doc-1",
		NavigationKind:       "committed",
		TransitionType:       "link",
		TransitionQualifiers: []string{},
		Source:               "edge_extension",
	}
}

func TestParseAndValidateEvent(t *testing.T) {
	payload, err := json.Marshal(validEvent())
	if err != nil {
		t.Fatal(err)
	}

	event, _, err := parseAndValidateEvent(payload)
	if err != nil {
		t.Fatal(err)
	}
	if event.URL != "https://example.test/login?token=%5BREDACTED%5D" {
		t.Fatalf("unexpected normalized URL: %s", event.URL)
	}
}

func TestRejectsUnsupportedScheme(t *testing.T) {
	event := validEvent()
	event.URL = "file:///C:/secret.txt"
	payload, _ := json.Marshal(event)

	if _, _, err := parseAndValidateEvent(payload); err == nil {
		t.Fatal("expected unsupported scheme to be rejected")
	}
}

func TestRunWritesEventAndAcknowledges(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "navigation.json")
	t.Setenv("PHISHING_DETECTION_LOG_FILE", logPath)

	payload, _ := json.Marshal(validEvent())
	var input bytes.Buffer
	if err := binary.Write(&input, binary.LittleEndian, uint32(len(payload))); err != nil {
		t.Fatal(err)
	}
	input.Write(payload)

	var output bytes.Buffer
	if err := run(&input, &output); err != nil {
		t.Fatal(err)
	}

	var responseLength uint32
	if err := binary.Read(&output, binary.LittleEndian, &responseLength); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, responseLength)
	if _, err := output.Read(response); err != nil {
		t.Fatal(err)
	}
	var ack acknowledgement
	if err := json.Unmarshal(response, &ack); err != nil {
		t.Fatal(err)
	}
	if !ack.Accepted || ack.EventID != "event-1" {
		t.Fatalf("unexpected acknowledgement: %+v", ack)
	}

	written, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(written), []byte{'\n'})
	if len(lines) != 1 {
		t.Fatalf("expected one JSONL record, got %d", len(lines))
	}
	var stored navigationEvent
	if err := json.Unmarshal(lines[0], &stored); err != nil {
		t.Fatal(err)
	}
	if stored.EventID != "event-1" {
		t.Fatalf("unexpected stored event: %+v", stored)
	}
}

func TestRunRejectsInvalidEventWithoutWriting(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "navigation.json")
	t.Setenv("PHISHING_DETECTION_LOG_FILE", logPath)

	payload := []byte(`{"schema_version":1,"event_id":"bad","url":"not a URL"}`)
	var input bytes.Buffer
	_ = binary.Write(&input, binary.LittleEndian, uint32(len(payload)))
	input.Write(payload)

	var output bytes.Buffer
	if err := run(&input, &output); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Fatalf("invalid event unexpectedly created a log: %v", err)
	}
}
