// core/sync.go
package core

import (
	interfaces "altica_node/utils"
	"encoding/json"
	"fmt"
	"time"

	"github.com/bits-and-blooms/bloom/v3"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/sirupsen/logrus"
)

// StateSnapshot represents a point-in-time state
type StateSnapshot struct {
	StateRoot []byte             `json:"state_root"`
	Timestamp time.Time          `json:"timestamp"`
	Version   int64              `json:"version"`
	Filter    *bloom.BloomFilter `json:"filter"`
}

// SyncManager manages the synchronization of records between peers
type SyncManager struct {
	store *RecordStore
	log   *logrus.Logger
}

// NewSyncManager creates a new sync manager
func NewSyncManager(store *RecordStore) *SyncManager {
	return &SyncManager{
		store: store,
		log:   logrus.New(),
	}
}

func (n *Node) handleRecordUpdates(sub *pubsub.Subscription) {
	fmt.Println("Listening for record updates...")
	for {
		msg, err := sub.Next(n.Context)
		fmt.Println("Receiving record update...")
		if err != nil {
			n.log.WithError(err).Error("Failed to read update")
			continue
		}
		fmt.Println("!Receiving record update...")

		var recordMsg interfaces.RecordMessage
		if err := json.Unmarshal(msg.Data, &recordMsg); err != nil {
			n.log.WithError(err).Error("Failed to unmarshal record message")
			continue
		}
		fmt.Println("successfully unmarshalled", recordMsg.Version, n.Store.GetCurrentVersion())

		switch recordMsg.Type {
		case "snapshot":
			continue
		case "registration_intent":
			// Each peer votes on the record
			n.handleRegistrationIntent(recordMsg)
		case "vote":
			continue
		}
	}
}
