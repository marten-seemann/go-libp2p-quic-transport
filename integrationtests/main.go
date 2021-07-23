package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/transport"
	libp2pquic "github.com/libp2p/go-libp2p-quic-transport"
	ma "github.com/multiformats/go-multiaddr"
	"golang.org/x/sync/errgroup"

	"github.com/libp2p/go-libp2p-quic-transport/integrationtests/conn"
	"github.com/libp2p/go-libp2p-quic-transport/integrationtests/stream"
)

func main() {
	hostKeyFile := flag.String("key", "", "file containing the libp2p private key")
	peerKeyFile := flag.String("peerkey", "", "file containing the libp2p private key of the peer")
	addrStr := flag.String("addr", "", "address to listen on (for the server) or to dial (for the client)")
	test := flag.String("test", "", "test name")
	role := flag.String("role", "", "server or client")
	flag.Parse()

	hostKey, peerPubKey, err := readKeys(*hostKeyFile, *peerKeyFile)
	if err != nil {
		log.Fatal(err)
	}
	addr, err := ma.NewMultiaddr(*addrStr)
	if err != nil {
		log.Fatal(err)
	}

	switch *role {
	case "server":
		if err := runServer(hostKey, peerPubKey, addr, *test); err != nil {
			log.Fatal(err)
		}
	case "client":
		if err := runClient(hostKey, peerPubKey, addr, *test); err != nil {
			log.Fatal(err)
		}
	}
}

// We pass in both the private keys of host and peer.
// We never use the private key of the peer though.
// That's why this function returns the peer's public key.
func readKeys(hostKeyFile, peerKeyFile string) (crypto.PrivKey, crypto.PubKey, error) {
	// read the host key
	hostKeyBytes, err := ioutil.ReadFile(hostKeyFile)
	if err != nil {
		return nil, nil, err
	}
	hostKey, err := crypto.UnmarshalPrivateKey(hostKeyBytes)
	if err != nil {
		return nil, nil, err
	}
	// read the peers key
	peerKeyBytes, err := ioutil.ReadFile(peerKeyFile)
	if err != nil {
		return nil, nil, err
	}
	peerKey, err := crypto.UnmarshalPrivateKey(peerKeyBytes)
	if err != nil {
		return nil, nil, err
	}
	return hostKey, peerKey.GetPublic(), nil
}

func runServer(hostKey crypto.PrivKey, peerKey crypto.PubKey, addr ma.Multiaddr, test string) error {
	tr, err := libp2pquic.NewTransport(hostKey, nil, nil)
	if err != nil {
		return err
	}
	ln, err := tr.Listen(addr)
	if err != nil {
		return err
	}
	conn, err := ln.Accept()
	if err != nil {
		return err
	}
	if test == "handshake-failure" {
		return errors.New("didn't expect to accept a connection in the handshake-failure test")
	}
	defer ln.Close()
	if !conn.RemotePublicKey().Equals(peerKey) {
		return errors.New("mismatching public keys")
	}
	clientPeerID, err := peer.IDFromPublicKey(peerKey)
	if err != nil {
		return err
	}
	if conn.RemotePeer() != clientPeerID {
		return fmt.Errorf("remote Peer ID mismatch. Got %s, expected %s", conn.RemotePeer().Pretty(), clientPeerID.Pretty())
	}
	var g errgroup.Group
	for {
		st, err := conn.AcceptStream()
		if err != nil {
			break
		}
		str := stream.WrapStream(st)
		g.Go(func() error {
			data, err := ioutil.ReadAll(str)
			if err != nil {
				return err
			}
			if err := str.CloseRead(); err != nil {
				return err
			}
			if _, err := str.Write(data); err != nil {
				return err
			}
			return str.CloseWrite()
		})
	}
	return g.Wait()
}

func runClient(hostKey crypto.PrivKey, serverKey crypto.PubKey, addr ma.Multiaddr, test string) error {
	tr, err := libp2pquic.NewTransport(hostKey, nil, nil)
	if err != nil {
		return err
	}
	switch test {
	case "single-transfer":
		return testSingleFileTransfer(tr, serverKey, addr)
	case "multi-transfer":
		return testMultipleFileTransfer(tr, serverKey, addr)
	case "handshake-failure":
		return testHandshakeFailure(tr, serverKey, addr)
	default:
		return errors.New("unknown test")
	}
}

func testSingleFileTransfer(tr transport.Transport, serverKey crypto.PubKey, addr ma.Multiaddr) error {
	serverPeerID, err := peer.IDFromPublicKey(serverKey)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := tr.Dial(ctx, addr, serverPeerID)
	if err != nil {
		return fmt.Errorf("dial failed: %w", err)
	}
	defer c.Close()
	if !c.RemotePublicKey().Equals(serverKey) {
		return errors.New("mismatching public keys")
	}
	if c.RemotePeer() != serverPeerID {
		return fmt.Errorf("remote Peer ID mismatch. Got %s, expected %s", c.RemotePeer().Pretty(), serverPeerID.Pretty())
	}
	st, err := conn.OpenStream(context.Background(), c)
	if err != nil {
		return err
	}
	str := stream.WrapStream(st)
	data := make([]byte, 1<<15)
	rand.Read(data)
	if _, err := str.Write(data); err != nil {
		return err
	}
	if err := str.CloseWrite(); err != nil {
		return err
	}
	echoed, err := ioutil.ReadAll(str)
	if err != nil {
		return err
	}
	if !bytes.Equal(data, echoed) {
		return errors.New("echoed data does not match")
	}
	return nil
}

func testMultipleFileTransfer(tr transport.Transport, serverKey crypto.PubKey, addr ma.Multiaddr) error {
	serverPeerID, err := peer.IDFromPublicKey(serverKey)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := tr.Dial(ctx, addr, serverPeerID)
	if err != nil {
		return fmt.Errorf("dial failed: %w", err)
	}
	defer c.Close()
	if !c.RemotePublicKey().Equals(serverKey) {
		return errors.New("mismatching public keys")
	}
	if c.RemotePeer() != serverPeerID {
		return fmt.Errorf("remote Peer ID mismatch. Got %s, expected %s", c.RemotePeer().Pretty(), serverPeerID.Pretty())
	}
	var g errgroup.Group
	for i := 0; i < 2000; i++ {
		g.Go(func() error {
			st, err := conn.OpenStream(context.Background(), c)
			if err != nil {
				return err
			}
			str := stream.WrapStream(st)
			data := make([]byte, 1<<9)
			rand.Read(data)
			if _, err := str.Write(data); err != nil {
				return err
			}
			if err := str.CloseWrite(); err != nil {
				return err
			}
			echoed, err := ioutil.ReadAll(str)
			if err != nil {
				return err
			}
			if !bytes.Equal(data, echoed) {
				return errors.New("echoed data does not match")
			}
			return nil
		})
	}
	return g.Wait()
}

func testHandshakeFailure(tr transport.Transport, serverKey crypto.PubKey, addr ma.Multiaddr) error {
	serverPeerID, err := peer.IDFromPublicKey(serverKey)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = tr.Dial(ctx, addr, serverPeerID)
	if err == nil {
		return errors.New("expected the handshake to fail")
	}
	if !strings.Contains(err.Error(), "CRYPTO_ERROR") || !strings.Contains(err.Error(), "peer IDs don't match") {
		return fmt.Errorf("got unexpected error: %w", err)
	}
	return nil
}
