package gpi

import (
  "fmt"
  "strings"
  "testing"

  "github.com/google/gopacket"
  "github.com/google/gopacket/pcap"
)

type ProtoTest struct{
  Expected int
  Proto Protocol
}

type ProtoTests []ProtoTest

func (tests ProtoTests) String() string {
  var result strings.Builder
  for i, test := range tests {
    if test.Expected > 0 {
      result.WriteString(
        fmt.Sprintf("#%d\t%s found\t%d time(s)\n", i, test.Proto, test.Expected))
    }
  }
  return result.String()
}

func testPCAPFile(pkgName string, tests ProtoTests, t *testing.T) {
  var protocols = ProtoTests{
    { Proto: ProtocolICMPv4, Expected: 0 },
    { Proto: ProtocolICMPv6, Expected: 0 },
    { Proto: ProtocolHTTP, Expected: 0 },
    { Proto: ProtocolTLS, Expected: 0 },
    { Proto: ProtocolSSL, Expected: 0 },
    { Proto: ProtocolFTP, Expected: 0 },
    { Proto: ProtocolSSH, Expected: 0 },
    { Proto: ProtocolSMTP, Expected: 0 },
    { Proto: ProtocolDNS, Expected: 0 },
    { Proto: ProtocolTCP, Expected: 0 },
    { Proto: ProtocolUDP, Expected: 0 },
    { Proto: ProtocolUnknown, Expected: 0 },
  }

  for _, protocol := range tcpPorts {
    protocols = append(protocols, ProtoTest{ Proto: protocol, Expected: 0 })
  }

  for _, protocol := range udpPorts {
    protocols = append(protocols, ProtoTest{ Proto: protocol, Expected: 0 })
  }

  var packetCount int
  var testPacketCount int

  handle, err := pcap.OpenOffline(pkgName)
  if err != nil {
    t.Errorf("expected nil, got %s", err.Error())
  }

  detections := make(map[Protocol]int)
  source := gopacket.NewPacketSource(handle, handle.LinkType())
  for packet := range source.Packets() {
    detection := Classify(packet)
    detections[detection] += 1
    packetCount++
  }

  for _, userTest := range tests {
    for i, test := range protocols {
      if test.Proto == userTest.Proto {
        protocols[i].Expected = userTest.Expected
      }
    }
    testPacketCount += userTest.Expected
  }

  for i, test := range protocols {
    count, found := detections[test.Proto];
    if test.Expected == 0 && found {
      t.Errorf("#%d expected %d packets of type %s, got %d",
        i, test.Expected, test.Proto, count)
    } else if found && detections[test.Proto] != test.Expected {
      t.Errorf("#%d expected %d packets of type %s, got %d",
        i, test.Expected, test.Proto, detections[test.Proto])
    }
  }

  if packetCount != testPacketCount {
    t.Errorf("expected %d, got %d", testPacketCount, packetCount)
  }

  fmt.Printf("%s:\n%s\n", pkgName, protocols)
}
