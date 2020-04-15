package gpi

import (
  "testing"

  "github.com/google/gopacket"
  "github.com/google/gopacket/pcap"
)

func TestMixedTraffic_SMTP_TLS(t *testing.T) {
  tests := ProtoTests{
    {Expected: 14, Proto: ProtocolTCP},
    {Expected: 5, Proto: ProtocolSMTP},
    {Expected: 17, Proto: ProtocolTLS},
    {Expected: 0, Proto: ProtocolUnknown},
  }

  testPCAPFile("samples/SMTP+TLS.pcap", tests, t)
}

func TestMixedTraffic_DNS_HTTP_TLS(t *testing.T) {
  tests := ProtoTests{
    {Expected: 8, Proto: ProtocolDNS},
    {Expected: 32, Proto: ProtocolTCP},
    {Expected: 2, Proto: ProtocolHTTP},
    {Expected: 22, Proto: ProtocolTLS},
    {Expected: 0, Proto: ProtocolUnknown},
  }

  testPCAPFile("samples/DNS+HTTP+TLS.pcap", tests, t)
}

func BenchmarkMixedTraffic(b *testing.B) {
  handle, err := pcap.OpenOffline("samples/DNS+HTTP+TLS.pcap")
  if err != nil {
    b.Errorf("expected nil, got %s", err.Error())
  }

  source := gopacket.NewPacketSource(handle, handle.LinkType())
  b.Run("classify DNS, HTTP and HTTPs sample", func(b *testing.B) {
    for packet := range source.Packets() {
      _ = Classify(packet)
    }
  })
}
