package core

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	// "github.com/ipfs/boxo/ipns"
	"github.com/ipfs/go-datastore/query"
	leveldb "github.com/ipfs/go-ds-leveldb"
	libp2p "github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	pstoreds "github.com/libp2p/go-libp2p-peerstore/pstoreds"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	record "github.com/libp2p/go-libp2p-record"
	"github.com/libp2p/go-libp2p/core/crypto"
	host "github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"

	// routing "github.com/libp2p/go-libp2p/core/routing"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	routingdiscovery "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	libp2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	"github.com/multiformats/go-multiaddr"
	"github.com/sirupsen/logrus"
)

type LogLevel string

const (
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
)

type NodeOptions struct {
	PrivateKey crypto.PrivKey
	DataDir    string
	LogLevel   LogLevel
}

type Node struct {
	Host         host.Host
	DHT          *dht.IpfsDHT // custom altica DHT only
	PubSub       *pubsub.PubSub
	RecordsTopic *pubsub.Topic // joined once and reused
	Context      context.Context
	log          *logrus.Logger
	Store        *RecordStore
	lastSync     time.Time
}

// Bootstrap nodes
var bootstrapPeers = []string{
	"/dns4/6.tcp.eu.ngrok.io/tcp/19164/p2p/12D3KooWH6hNr8GtqXpmpB7oPshmKnA58G7UuYR5YXdnJxEAoT5s",
}

type PermissiveValidator struct{}

func (PermissiveValidator) Validate(key string, value []byte) error         { return nil }
func (PermissiveValidator) Select(key string, values [][]byte) (int, error) { return 0, nil }

func NewNode(ctx context.Context, opts NodeOptions) (*Node, error) {
	logger := logrus.New()

	// Set log level
	switch opts.LogLevel {
	case LogLevelDebug:
		logger.SetLevel(logrus.DebugLevel)
	case LogLevelInfo:
		logger.SetLevel(logrus.InfoLevel)
	case LogLevelWarn:
		logger.SetLevel(logrus.WarnLevel)
	case LogLevelError:
		logger.SetLevel(logrus.ErrorLevel)
	default:
		logger.SetLevel(logrus.InfoLevel)
	}

	// Create peers datastore
	peerstorePath := filepath.Join(opts.DataDir, "peerstore")
	ds, err := leveldb.NewDatastore(peerstorePath, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create peers datastore: %w", err)
	}

	// Create records datastore
	recordsPath := filepath.Join(opts.DataDir, "records")
	recordsDs, err := leveldb.NewDatastore(recordsPath, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create records datastore: %w", err)
	}

	// Check if this is a fresh startup by looking for any records
	hasRecords := false
	results, err := recordsDs.Query(ctx, query.Query{})
	if err != nil {
		return nil, fmt.Errorf("failed to query records: %w", err)
	}
	if r, err := results.Rest(); err == nil && len(r) > 0 {
		hasRecords = true
	}
	results.Close()

	ps, err := pstoreds.NewPeerstore(ctx, ds, pstoreds.DefaultOpts())
	if err != nil {
		return nil, fmt.Errorf("failed to create peerstore: %w", err)
	}

	// Create libp2p host with all options
	h, err := libp2p.New(
		libp2p.Identity(opts.PrivateKey),
		libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/0"),
		libp2p.Peerstore(ps),
		libp2p.NATPortMap(),
		libp2p.EnableAutoRelayWithPeerSource(func(ctx context.Context, numRelays int) <-chan peer.AddrInfo {
			fmt.Printf("Number of active relays requested: %d\n", numRelays)
			ch := make(chan peer.AddrInfo)
			close(ch)
			return ch
		}),
		libp2p.EnableHolePunching(),
		libp2p.Security(libp2ptls.ID, libp2ptls.New),
		libp2p.Security(noise.ID, noise.New),
		libp2p.Transport(tcp.NewTCPTransport),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create libp2p host: %w", err)
	}

	// Create custom altica DHT
	alticaValidators := record.NamespacedValidator{
		"altica": PermissiveValidator{},
	}
	alticaDHT, err := dht.New(ctx, h,
		dht.Mode(dht.ModeServer),
		dht.ProtocolPrefix("/altica"),
		dht.Validator(alticaValidators),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create altica DHT: %w", err)
	}

	// Create pubsub
	pubs, err := pubsub.NewGossipSub(ctx, h)
	if err != nil {
		return nil, fmt.Errorf("failed to create pubsub: %w", err)
	}

	// Join the records topic once and reuse
	recordsTopic, err := pubs.Join("altica-records")
	if err != nil {
		return nil, fmt.Errorf("failed to join records topic: %w", err)
	}

	store := NewRecordStore(recordsDs, alticaDHT, ctx, h.ID().String())
	node := &Node{
		Host:         h,
		DHT:          alticaDHT,
		PubSub:       pubs,
		RecordsTopic: recordsTopic,
		Context:      ctx,
		log:          logger,
		Store:        store,
	}

	if !hasRecords {
		node.lastSync = time.Time{}
		logger.Info("Fresh startup detected, will sync all records from version 0")
	} else {
		lastSync, err := store.GetLastSyncTime()
		if err != nil {
			logger.WithError(err).Error("Failed to get last sync time from storage")
			restart := node.promptUserConfirmation("Failed to get last sync time. Start fresh sync from version 0?")
			if !restart {
				return nil, fmt.Errorf("cannot continue without sync time confirmation, please fix the storage or confirm fresh sync")
			}
			node.lastSync = time.Time{}
			logger.Info("Starting fresh sync from version 0")
		} else {
			node.lastSync = lastSync
			logger.WithField("lastSync", lastSync).Info("Continuing from last sync time")
		}
	}
	return node, nil
}

func (n *Node) Bootstrap() error {
	// Convert bootstrap peer strings to multiaddrs
	var bootstrapMultiaddrs []multiaddr.Multiaddr
	for _, addr := range bootstrapPeers {
		ma, err := multiaddr.NewMultiaddr(addr)
		if err != nil {
			n.log.WithError(err).Error("Invalid bootstrap address")
			return fmt.Errorf("invalid bootstrap address: %w", err)
		}
		bootstrapMultiaddrs = append(bootstrapMultiaddrs, ma)
	}

	// Bootstrap DHT
	if err := n.DHT.Bootstrap(n.Context); err != nil {
		n.log.WithError(err).Error("Failed to bootstrap DHT")
		return fmt.Errorf("failed to bootstrap DHT: %w", err)
	}

	// Connect to bootstrap peers
	var wg sync.WaitGroup
	for _, peerAddr := range bootstrapMultiaddrs {
		peerInfo, err := peer.AddrInfoFromP2pAddr(peerAddr)
		if err != nil {
			n.log.WithError(err).Debug("Failed to parse peer address")
			continue
		}
		wg.Add(1)
		go func(pi peer.AddrInfo) {
			defer wg.Done()
			if err := n.Host.Connect(n.Context, pi); err != nil {
				n.log.WithFields(logrus.Fields{
					"peer":  pi.ID.String(),
					"error": err,
				}).Debug("Failed to connect to bootstrap peer")
			}
		}(*peerInfo)
	}
	wg.Wait()

	routingDiscovery := routingdiscovery.NewRoutingDiscovery(n.DHT)
	routingDiscovery.Advertise(n.Context, "altica-dns-discovery")

	n.log.Debug("Advertising for peers...")

	go func() {
		for {
			peerChan, err := routingDiscovery.FindPeers(n.Context, "altica-dns-discovery")
			if err != nil {
				n.log.WithError(err).Debug("Failed to find peers")
				time.Sleep(time.Minute)
				continue
			}

			for peer := range peerChan {
				if peer.ID == n.Host.ID() {
					n.log.Debug("Skipping self peer")
					continue // Don't connect to self
				}
				if err := n.Host.Connect(n.Context, peer); err != nil {
					n.log.WithFields(logrus.Fields{
						"peer":  peer.ID.String(),
						"error": err,
					}).Debug("Failed to connect to peer")
				} else {
					n.log.WithField("peer", peer.ID.String()).Info("Connected to peer")
				}
			}
			time.Sleep(time.Minute)
		}
	}()

	_ = mdns.NewMdnsService(n.Host, "altica-mdns", n)

	// Start record synchronization
	if err := n.StartRecordSync(); err != nil {
		return fmt.Errorf("failed to start record sync: %w", err)
	}

	return nil
}

func (n *Node) SubscribeToRecords() error {
	topic, err := n.PubSub.Join("altica-dns-records")
	fmt.Println("Joining topic:", topic)
	if err != nil {
		return fmt.Errorf("failed to join pubsub topic: %w", err)
	}

	sub, err := topic.Subscribe()
	if err != nil {
		return fmt.Errorf("failed to subscribe to topic: %w", err)
	}

	go func() {
		for {
			msg, err := sub.Next(n.Context)
			if err != nil {
				fmt.Println("Error reading message:", err)
				continue
			}
			fmt.Printf("Record update from %s: %s\n", msg.GetFrom().String(), string(msg.Data))
			// TODO: handle/verify the record data
		}
	}()

	return nil
}

// HandlePeerFound connects to peers discovered via mDNS. Implements mdns.Notifee
func (n *Node) HandlePeerFound(pi peer.AddrInfo) {
	if pi.ID == n.Host.ID() {
		fmt.Println("Skipping self peer in HandlePeerFound")
		return // Don't connect to self
	}

	if err := n.Host.Connect(n.Context, pi); err != nil {
		fmt.Println("Error connecting to mDNS peer:", err)
	} else {
		fmt.Println("Connected to mDNS peer:", pi.ID.String())
	}
}

// ListPeers returns information about all connected peers
func (n *Node) ListPeers() []peer.AddrInfo {
	var peers []peer.AddrInfo
	for _, p := range n.Host.Network().Peers() {
		addrs := n.Host.Peerstore().Addrs(p)
		peers = append(peers, peer.AddrInfo{
			ID:    p,
			Addrs: addrs,
		})
	}
	return peers
}

// PrettyPrintPeers prints connected peers in a human-readable format
func (n *Node) PrettyPrintPeers() {
	peers := n.ListPeers()
	n.log.WithField("count", len(peers)).Info("Connected peers")

	for i, p := range peers {
		n.log.WithFields(logrus.Fields{
			"index":     i + 1,
			"id":        p.ID.String(),
			"addresses": p.Addrs,
		}).Debug("Peer details")
	}
}

func (n *Node) promptUserConfirmation(prompt string) bool {
	fmt.Print(prompt + " [Y/n]: ")
	var response string
	fmt.Scanln(&response)
	return response == "" || response == "Y" || response == "y"
}
