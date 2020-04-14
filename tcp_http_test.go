package gpi

import (
  "testing"

  "github.com/google/gopacket"
  "github.com/google/gopacket/pcap"
)

func TestTCPHTTP(t *testing.T) {
  var i int
  handle, err := pcap.OpenOffline("samples/HTTP.pcap")
  if err != nil {
    t.Errorf("expected nil, got %s", err.Error())
  }

  source := gopacket.NewPacketSource(handle, handle.LinkType())
  for packet := range source.Packets() {
    protocol := Classify(packet)
    if protocol != ProtocolHTTP {
      t.Errorf("%d# expected %s, got %s", i, ProtocolHTTP, protocol)
    }
    i++
  }

  if i != 2 {
    t.Errorf("expected %d, got %d", 2, i)
  }
}
