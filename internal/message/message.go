// Contains the message format for the packet payload
package message

// Message struct contains information sent between client and host
type Message struct {
	Type string `json:"type"` // Message type
	DstIP   string `json:"dstip"` // Destination IP -- The target host
	SrcIP string `json:"srcip,omitempty"` // Source IP -- The control host
	SrcPort string `json:"srcport,omitempty"` // Source Port -- Source port for reverse shell
	Data string `json:"data"` // Payload for commands
}
