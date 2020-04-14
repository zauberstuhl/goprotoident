package gpi

import (
  "testing"

  "github.com/google/gopacket"
  "github.com/google/gopacket/pcap"
)

func TestUDPDNS(t *testing.T) {
  var i int
  handle, err := pcap.OpenOffline("samples/DNS.pcap")
  if err != nil {
    t.Errorf("expected nil, got %s", err.Error())
  }

  source := gopacket.NewPacketSource(handle, handle.LinkType())
  for packet := range source.Packets() {
    protocol := Classify(packet)
    if protocol != ProtocolDNS {
      t.Errorf("%d# expected %s, got %s", i, ProtocolDNS, protocol)
    }
    i++
  }

  if i != 4 {
    t.Errorf("expected %d, got %d", 4, i)
  }
}
