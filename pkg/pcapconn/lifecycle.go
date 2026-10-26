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
		// Stop packet-processing workers.
		c.cancel()

		// Close the application-facing TCP connection.
		if c.Conn != nil {
			c.closeErr = errors.Join(
				c.closeErr,
				c.Conn.Close(),
			)
		}

		// Stop gVisor's networking stack.
		c.stack.Close()

		// Wait for ingress and egress workers to exit.
		// Assumes ReadPacketData is bounded by the
		// configured capture timeout.
		c.workers.Wait()

		// Release networking resources.
		c.link.Close()
		c.handle.Close()

		// Wait for gVisor cleanup.
		c.stack.Wait()

		// Remove firewall isolation.
		if c.isolator != nil {
			releaseCtx, cancel := context.WithTimeout(
				context.Background(),
				2*time.Second,
			)

			err := c.isolator.Release(
				releaseCtx,
				c.srcPort,
			)
			cancel()

			if err != nil {
				c.closeErr = errors.Join(
					c.closeErr,
					fmt.Errorf(
						"failed to release flow isolator: %w",
						err,
					),
				)
			}
		}

		// Collect worker failures.
		c.mu.Lock()
		workerErr := c.workerErr
		c.mu.Unlock()

		c.closeErr = errors.Join(c.closeErr, workerErr)
	})

	return c.closeErr
}
