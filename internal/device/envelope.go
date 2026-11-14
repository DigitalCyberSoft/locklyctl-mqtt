// Package device is the MQTT broker and the Lockly device-channel protocol:
// it authenticates locks, tracks which are online, relays BLE frames to them
// and reads back their responses, state callbacks and access-log events.
//
// Topology (matches Lockly, see CONTRACT.md): a lock subscribes to
// "client/<clientId>" for commands and publishes to "server" for everything it
// sends. This server is the broker and the backend both; locklyctl reaches a
// lock through the REST /api/senddata, which this package turns into a
// device-channel command.
package device

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// Device-channel message names (header.name).
const (
	NameCommandRequest   = "lockCommandRequest"
	NameCommandResponse  = "lockCommandResponse"
	NameStateCallback    = "deviceStateCallback"
	NameEventLogRequest  = "lockEventLogQueryRequest"
	NameEventLogResponse = "lockEventLogQueryResponse"
	NameFirmwareRequest  = "firmwareUpgradeRequest"
	NameFirmwareProgress = "firmwareUpgradeProgress"
	NameFirmwareFailure  = "firmwareUpgradeFailure"
	NameException        = "exception"

	Namespace = "com.lockly"

	// TopicServer is where clients publish to the server; TopicClientPrefix +
	// clientId is where the server publishes to one client.
	TopicServer       = "server"
	TopicClientPrefix = "client/"

	// CommandForward is the commandName for a relayed BLE frame.
	CommandForward = "forward"
)

// Header is the envelope header.
type Header struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	RequestID string `json:"requestId,omitempty"`
	Timestamp int64  `json:"timestamp,omitempty"`
}

// Envelope is a device-channel message.
type Envelope struct {
	Header  Header          `json:"header"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// CommandPayload is the payload of a lockCommandRequest/Response. The BLE frame
// rides as CommandContent, base64 of the frame bytes.
type CommandPayload struct {
	DeviceID       string `json:"deviceId"`
	CommandName    string `json:"commandName,omitempty"`
	CommandContent string `json:"commandContent,omitempty"`
	Code           any    `json:"code,omitempty"`
	ErrorMessage   string `json:"errorMessage,omitempty"`
}

// StatePayload is the payload of a deviceStateCallback.
type StatePayload struct {
	DeviceID string `json:"deviceId"`
	States   []struct {
		StatusKey   string `json:"statusKey"`
		StatusValue string `json:"statusValue"`
	} `json:"states"`
}

func marshalEnvelope(name, requestID string, ts int64, payload any) ([]byte, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return json.Marshal(Envelope{
		Header:  Header{Namespace: Namespace, Name: name, RequestID: requestID, Timestamp: ts},
		Payload: raw,
	})
}

// frameToContent base64-encodes a BLE frame hex string for CommandContent.
func frameToContent(frameHex string) (string, error) {
	b, err := hex.DecodeString(strings.TrimSpace(frameHex))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// contentToFrame decodes a CommandContent back to an uppercase frame hex string.
func contentToFrame(content string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		return "", err
	}
	return strings.ToUpper(hex.EncodeToString(b)), nil
}

// codeIsSuccess reports whether a response Code field means success (0, "0",
// or absent). The Lockly backend uses 3005 for an offline device.
func codeIsSuccess(code any) bool {
	switch v := code.(type) {
	case nil:
		return true
	case float64:
		return v == 0
	case string:
		return v == "" || v == "0"
	case json.Number:
		return v.String() == "0"
	default:
		return false
	}
}
