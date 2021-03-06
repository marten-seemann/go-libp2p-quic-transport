package libp2pquic

import (
	"bytes"
	"net"
	"runtime/pprof"
	"strings"
	"time"

	"github.com/libp2p/go-netroute"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func (c *reuseConn) GetCount() int {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.refCount
}

func closeAllConns(reuse *reuse) {
	reuse.mutex.Lock()
	for _, conn := range reuse.global {
		for conn.GetCount() > 0 {
			conn.DecreaseCount()
		}
	}
	for _, conns := range reuse.unicast {
		for _, conn := range conns {
			for conn.GetCount() > 0 {
				conn.DecreaseCount()
			}
		}
	}
	reuse.mutex.Unlock()
}

func OnPlatformsWithRoutingTablesIt(description string, f interface{}) {
	if _, err := netroute.New(); err == nil {
		It(description, f)
	} else {
		PIt(description, f)
	}
}

var _ = Describe("Reuse", func() {
	var reuse *reuse

	BeforeEach(func() {
		reuse = newReuse()
	})

	AfterEach(func() {
		isGarbageCollectorRunning := func() bool {
			var b bytes.Buffer
			pprof.Lookup("goroutine").WriteTo(&b, 1)
			return strings.Contains(b.String(), "go-libp2p-quic-transport.(*reuse).gc")
		}

		Expect(reuse.Close()).To(Succeed())
		Expect(isGarbageCollectorRunning()).To(BeFalse())
	})

	Context("creating and reusing connections", func() {
		AfterEach(func() { closeAllConns(reuse) })

		It("creates a new global connection when listening on 0.0.0.0", func() {
			addr, err := net.ResolveUDPAddr("udp4", "0.0.0.0:0")
			Expect(err).ToNot(HaveOccurred())
			conn, err := reuse.Listen("udp4", addr)
			Expect(err).ToNot(HaveOccurred())
			Expect(conn.GetCount()).To(Equal(1))
		})

		It("creates a new global connection when listening on [::]", func() {
			addr, err := net.ResolveUDPAddr("udp6", "[::]:1234")
			Expect(err).ToNot(HaveOccurred())
			conn, err := reuse.Listen("udp6", addr)
			Expect(err).ToNot(HaveOccurred())
			Expect(conn.GetCount()).To(Equal(1))
		})

		It("creates a new global connection when dialing", func() {
			addr, err := net.ResolveUDPAddr("udp4", "1.1.1.1:1234")
			Expect(err).ToNot(HaveOccurred())
			conn, err := reuse.Dial("udp4", addr)
			Expect(err).ToNot(HaveOccurred())
			Expect(conn.GetCount()).To(Equal(1))
			laddr := conn.LocalAddr().(*net.UDPAddr)
			Expect(laddr.IP.String()).To(Equal("0.0.0.0"))
			Expect(laddr.Port).ToNot(BeZero())
		})

		It("reuses a connection it created for listening when dialing", func() {
			// listen
			addr, err := net.ResolveUDPAddr("udp4", "0.0.0.0:0")
			Expect(err).ToNot(HaveOccurred())
			lconn, err := reuse.Listen("udp4", addr)
			Expect(err).ToNot(HaveOccurred())
			Expect(lconn.GetCount()).To(Equal(1))
			// dial
			raddr, err := net.ResolveUDPAddr("udp4", "1.1.1.1:1234")
			Expect(err).ToNot(HaveOccurred())
			conn, err := reuse.Dial("udp4", raddr)
			Expect(err).ToNot(HaveOccurred())
			Expect(conn.GetCount()).To(Equal(2))
		})

		OnPlatformsWithRoutingTablesIt("reuses a connection it created for listening on a specific interface", func() {
			router, err := netroute.New()
			Expect(err).ToNot(HaveOccurred())

			raddr, err := net.ResolveUDPAddr("udp4", "1.1.1.1:1234")
			Expect(err).ToNot(HaveOccurred())
			_, _, ip, err := router.Route(raddr.IP)
			Expect(err).ToNot(HaveOccurred())
			// listen
			addr, err := net.ResolveUDPAddr("udp4", ip.String()+":0")
			Expect(err).ToNot(HaveOccurred())
			lconn, err := reuse.Listen("udp4", addr)
			Expect(err).ToNot(HaveOccurred())
			Expect(lconn.GetCount()).To(Equal(1))
			// dial
			conn, err := reuse.Dial("udp4", raddr)
			Expect(err).ToNot(HaveOccurred())
			Expect(conn.GetCount()).To(Equal(2))
		})
	})

	It("garbage collects connections once they're not used any more for a certain time", func() {
		numGlobals := func() int {
			reuse.mutex.Lock()
			defer reuse.mutex.Unlock()
			return len(reuse.global)
		}

		maxUnusedDuration = 100 * time.Millisecond

		addr, err := net.ResolveUDPAddr("udp4", "0.0.0.0:0")
		Expect(err).ToNot(HaveOccurred())
		lconn, err := reuse.Listen("udp4", addr)
		Expect(err).ToNot(HaveOccurred())
		Expect(lconn.GetCount()).To(Equal(1))

		closeTime := time.Now()
		lconn.DecreaseCount()

		for {
			num := numGlobals()
			if closeTime.Add(maxUnusedDuration).Before(time.Now()) {
				break
			}
			Expect(num).To(Equal(1))
			time.Sleep(2 * time.Millisecond)
		}
		Eventually(numGlobals).Should(BeZero())
	})
})
