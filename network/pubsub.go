package network

import (
	"context"
	"encoding/json"
	"log"

	"altica_node/core"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	host "github.com/libp2p/go-libp2p/core/host"
)

// PubSubService wraps pubsub for record exchange
type PubSubService struct {
	PubSub *pubsub.PubSub
	Topic  *pubsub.Topic
	Sub    *pubsub.Subscription
	Ctx    context.Context
	Store  *core.RecordStore
}

// NewPubSubService sets up pubsub and subscribes to the records topic
func NewPubSubService(ctx context.Context, h host.Host) (*PubSubService, error) {
	ps, err := pubsub.NewGossipSub(ctx, h)
	if err != nil {
		return nil, err
	}
	topic, err := ps.Join("altica-dns-records")
	if err != nil {
		return nil, err
	}
	sub, err := topic.Subscribe()
	if err != nil {
		return nil, err
	}

	service := &PubSubService{
		PubSub: ps,
		Topic:  topic,
		Sub:    sub,
		Ctx:    ctx,
		Store:  core.NewRecordStore(),
	}

	go service.handleMessages()
	return service, nil
}

// PublishRecord publishes a signed record to the pubsub topic
func (ps *PubSubService) PublishRecord(record *core.Record) error {
	data, err := record.Serialize()
	if err != nil {
		return err
	}
	return ps.Topic.Publish(ps.Ctx, data)
}

// handleMessages listens for new records and adds them to the store if valid
func (ps *PubSubService) handleMessages() {
	for {
		msg, err := ps.Sub.Next(ps.Ctx)
		if err != nil {
			log.Println("PubSub receive error:", err)
			continue
		}
		var rec core.Record
		if err := json.Unmarshal(msg.Data, &rec); err != nil {
			log.Println("Failed to unmarshal record:", err)
			continue
		}
		if err := ps.Store.Add(&rec); err != nil {
			log.Println("Rejected record from", msg.GetFrom().String(), ":", err)
			continue
		}
		log.Printf("Received valid record for %s from %s\n", rec.Domain, msg.GetFrom().String())
	}
}

// GetRecord returns a record from the local store
func (ps *PubSubService) GetRecord(domain string) (*core.Record, bool) {
	return ps.Store.Get(domain)
}
