package pcapconn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/MeHungr/doodlebob/pkg/isolator"
	"github.com/google/gopacket/pcap"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// ownedConn keeps the capture handle and workers alive until the connection closes.
type ownedConn struct {
	net.Conn
	stack     *stack.Stack
	link      *channel.Endpoint
	handle    *pcap.Handle
	cancel    context.CancelFunc
	workers   sync.WaitGroup
	once      sync.Once
	mu        sync.Mutex
	workerErr error
	closeErr  error
	isolator  isolator.FlowIsolator
	srcPort   int
}

// CloseWrite sends FIN while leaving the packet workers alive to finish teardown.
func (c *ownedConn) CloseWrite() error {
	conn, ok := c.Conn.(interface{ CloseWrite() error })
	if !ok {
		return fmt.Errorf("underlying connection does not support CloseWrite")
	}
	return conn.CloseWrite()
}

func (c *ownedConn) workerFailed(err error) {
	if err == nil {
		return
	}
	c.mu.Lock()
	c.workerErr = errors.Join(c.workerErr, err)
	c.mu.Unlock()
	c.cancel()
	// Wake a pending handshake or application read/write on an unusable link.
	c.stack.Close()
}

func (c *ownedConn) Close() error {
	c.once.Do(func() {
		c.cancel()
		if c.Conn != nil {
			c.closeErr = c.Conn.Close()
		}
		c.stack.Close()
		c.workers.Wait()
		c.link.Close()
		c.handle.Close()
		c.stack.Wait()
		c.mu.Lock()
		c.closeErr = errors.Join(c.closeErr, c.workerErr)
		c.mu.Unlock()
	})

	// Clean up host firewall modifications after network workers have ceased processing.
	if c.isolator != nil {
		releaseCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		if err := c.isolator.Release(releaseCtx, c.srcPort); err != nil {
			c.closeErr = errors.Join(c.closeErr, fmt.Errorf("failed to release flow isolator: %w", err))
		}
		cancel()
	}

	return c.closeErr
}
