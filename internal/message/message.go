// Contains the message format for the packet payload
package message

type Message struct {
	Type string `json:"type"`
	IP   string `json:"ip"`
	Data string `json:"data"`
}
