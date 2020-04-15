package gpi

import (
  "testing"

  "github.com/google/gopacket"
  "github.com/google/gopacket/pcap"
)

type ProtoTest struct{
  Expected int
  Proto Protocol
}

type ProtoTests []ProtoTest

func testPCAPFile(pkgName string, tests ProtoTests, t *testing.T) {
  var i int
  handle, err := pcap.OpenOffline(pkgName)
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

  var pkgCount int
  for _, test := range tests {
    pkgCount += test.Expected

    if detections[test.Proto.String()] != test.Expected {
      t.Errorf("expected %d packets of type %s, got %d",
        test.Expected, test.Proto, detections[test.Proto.String()])
    }
  }

  if i != pkgCount {
    t.Errorf("expected %d, got %d", pkgCount, i)
  }
}
