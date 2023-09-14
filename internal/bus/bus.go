package bus

import "github.com/wagoodman/go-partybus"

var publisher partybus.Publisher

func Set(p partybus.Publisher) {
	publisher = p
}

func Publish(event partybus.Event) {
	if publisher != nil {
		publisher.Publish(event)
	}
}
