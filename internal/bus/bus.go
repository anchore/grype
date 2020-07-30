package bus

import "github.com/wagoodman/go-partybus"

var publisher partybus.Publisher
var active bool

func SetPublisher(p partybus.Publisher) {
	publisher = p
	if p != nil {
		active = true
	}
}

func Publish(event partybus.Event) {
	if active {
		publisher.Publish(event)
	}
}
