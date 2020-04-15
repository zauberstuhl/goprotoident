package gpi

import "testing"

func TestUDPDNS(t *testing.T) {
  tests := ProtoTests{
    {Proto: ProtocolDNS, Expected: 4},
  }
  testPCAPFile("samples/DNS.pcap", tests, t)
}
