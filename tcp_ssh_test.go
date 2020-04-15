package gpi

import (
  "testing"

  "github.com/google/gopacket"
  "github.com/google/gopacket/pcap"
)

func TestTCPSSH(t *testing.T) {
  var i int
  handle, err := pcap.OpenOffline("samples/SSH.pcap")
  if err != nil {
    t.Errorf("expected nil, got %s", err.Error())
  }

  detections := make(map[string]int)
  source := gopacket.NewPacketSource(handle, handle.LinkType())
  for packet := range source.Packets() {
    detection := Classify(packet)
    detections[detection.String()] += 1
    i++
  }

  protoTest := []struct{
    Expected int
    Proto Protocol
  }{
    {Expected: 25, Proto: ProtocolTCP},
    {Expected: 13, Proto: ProtocolSSH},
    {Expected: 0, Proto: ProtocolUnknown},
  }

  for _, test := range protoTest {
    if detections[test.Proto.String()] != test.Expected {
      t.Errorf("expected %d packets of type %s, got %d",
        test.Expected, test.Proto, detections[test.Proto.String()])
    }
  }

  if i != 38 {
    t.Errorf("expected %d, got %d", 38, i)
  }
}
