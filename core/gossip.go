package core

import (
	interfaces "altica_node/utils"
	"context"
	"encoding/json"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/sirupsen/logrus"
)

const (
	GossipTopicNameBound = "altica-evm-namebound"
	GossipTopicRecords   = "altica-records"
	BloomFilterSize      = 100000
)

// GossipManager handles pubsub for both NameBound events and record sync
type GossipManager struct {
	ctx         context.Context
	Node        *Node // Reference to the Node for handling specific events
	pubsub      *pubsub.PubSub
	nameTopic   *pubsub.Topic
	recordTopic *pubsub.Topic
	nameSub     *pubsub.Subscription
	recordSub   *pubsub.Subscription
	log         *logrus.Logger
	// TODO: add/use a cache storage
	eventSeen   map[string]struct{} // deduplication cache for NameBound
	messageSeen map[string]struct{} // deduplication cache for RecordMessage
}

// NewGossipManager initializes libp2p and pubsub
func NewGossipManager(ctx context.Context, host host.Host, logger *logrus.Logger) (*GossipManager, error) {
	ps, err := pubsub.NewGossipSub(ctx, host)
	if err != nil {
		return nil, err
	}
	nameTopic, err := ps.Join(GossipTopicNameBound)
	if err != nil {
		return nil, err
	}
	recordTopic, err := ps.Join(GossipTopicRecords)
	if err != nil {
		return nil, err
	}
	nameSub, err := nameTopic.Subscribe()
	if err != nil {
		return nil, err
	}
	recordSub, err := recordTopic.Subscribe()
	if err != nil {
		return nil, err
	}
	return &GossipManager{
		ctx:         ctx,
		pubsub:      ps,
		nameTopic:   nameTopic,
		recordTopic: recordTopic,
		nameSub:     nameSub,
		recordSub:   recordSub,
		log:         logger,
		eventSeen:   make(map[string]struct{}),
		messageSeen: make(map[string]struct{}),
	}, nil
}

// Close cleans up the GossipManager resources
func (g *GossipManager) Close() error {
	g.log.Info("Closing GossipManager")
	g.nameSub.Cancel()
	g.recordSub.Cancel()
	if err := g.nameTopic.Close(); err != nil {
		g.log.WithError(err).Error("Failed to close NameBound topic")
	}
	if err := g.recordTopic.Close(); err != nil {
		g.log.WithError(err).Error("Failed to close RecordMessage topic")
	}
	return nil
}

// Start starts the GossipManager and its subscriptions
func (g *GossipManager) Start() error {
	g.log.Info("Starting GossipManager")
	// Start listening for NameBound events
	g.ListenNameBound(func(evt interfaces.NameBoundEvent) {
		g.log.WithFields(logrus.Fields{
			"resolver":  evt.Resolver.Hex(),
			"expiresAt": evt.ExpiresAt,
			"eventID":   evt.EventID,
		}).Info("Received NameBound event")
		g.handleNameBoundEvent(evt)
	})

	// Start listening for RecordMessages
	g.ListenRecordMessages(func(msg interfaces.RecordMessage) {
		g.log.WithFields(logrus.Fields{
			"type":    msg.Type,
			"version": msg.Version,
			"peerID":  msg.PeerID,
		}).Info("Received RecordMessage")
		g.handleRecordMessage(msg)
	})

	return nil
}

// PublishNameBound gossips a NameBound event
func (g *GossipManager) PublishNameBound(evt interfaces.NameBoundEvent) error {
	evt.Timestamp = time.Now()
	data, err := json.Marshal(evt)
	if err != nil {
		return err
	}
	return g.nameTopic.Publish(g.ctx, data)
}

// ListenNameBound listens for NameBound events and applies deduplication
func (g *GossipManager) ListenNameBound(handler func(interfaces.NameBoundEvent)) {
	go func() {
		for {
			msg, err := g.nameSub.Next(g.ctx)
			if err != nil {
				g.log.WithError(err).Error("Gossip subscription error (NameBound)")
				return
			}
			var evt interfaces.NameBoundEvent
			if err := json.Unmarshal(msg.Data, &evt); err != nil {
				g.log.WithError(err).Warn("Failed to decode NameBound gossip")
				continue
			}
			// Deduplication
			if _, seen := g.eventSeen[evt.EventID]; seen {
				continue
			}
			g.eventSeen[evt.EventID] = struct{}{}
			handler(evt)
		}
	}()
}

// PublishRecordMessage gossips a record sync message (batch, snapshot, intent, etc.)
func (g *GossipManager) PublishRecordMessage(msg interfaces.RecordMessage) error {
	msg.Timestamp = time.Now()
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return g.recordTopic.Publish(g.ctx, data)
}

// ListenRecordMessages listens for record sync messages and applies deduplication
func (g *GossipManager) ListenRecordMessages(handler func(interfaces.RecordMessage)) {
	go func() {
		for {
			msg, err := g.recordSub.Next(g.ctx)
			if err != nil {
				g.log.WithError(err).Error("Gossip subscription error (RecordMessage)")
				return
			}
			var recordMsg interfaces.RecordMessage
			// TODO: fix decoding issues with RecordMessage
			// json: cannot unmarshal object into Go struct field RecordMessage.records of type utils.Record
			if err := json.Unmarshal(msg.Data, &recordMsg); err != nil {
				g.log.WithError(err).Warn("Failed to decode RecordMessage gossip")
				continue
			}
			// Deduplication
			if recordMsg.MessageID != "" {
				if _, seen := g.messageSeen[recordMsg.MessageID]; seen {
					continue
				}
				g.messageSeen[recordMsg.MessageID] = struct{}{}
			}
			handler(recordMsg)
		}
	}()
}

// Example handler for NameBound event
func (g *GossipManager) handleNameBoundEvent(evt interfaces.NameBoundEvent) {
	// Update local record store with resolver address
	g.Node.handleNameBoundEvent(evt)
}

// Example handler for RecordMessage
func (g *GossipManager) handleRecordMessage(msg interfaces.RecordMessage) {
	// Process batch, snapshot, registration intent, etc.
	switch msg.Type {
	case "registration_intent":
		g.Node.handleRegistrationIntent(msg)
	}

}
