// Contains the message format for the packet payload
package message

// Magic header at beginning of all packets
var MagicHeader = []byte{0x44, 0x4F, 0x4F, 0x44, 0x4C, 0x45} // "DOODLE"

// Define custom type for Message Type field
type MessageType string

// The custom values
const (
	Command MessageType = "command"
	Heartbeat MessageType = "heartbeat"
	Shell MessageType = "shell"
)

// Message struct contains information sent between client and host
type Message struct {
	Type MessageType `json:"type"` // Message type
	DstIP   string `json:"dstip"` // Destination IP -- The target host
	SrcIP string `json:"srcip,omitempty"` // Source IP -- The control host
	SrcPort string `json:"srcport,omitempty"` // Source Port -- Source port for reverse shell
	Data string `json:"data"` // Payload for commands
}
