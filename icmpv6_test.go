package gpi

import "testing"

func TestICMPv6(t *testing.T) {
  tests := ProtoTests{
    {Expected: 49, Proto: ProtocolICMPv6},
    {Expected: 0, Proto: ProtocolUnknown},
  }
  testPCAPFile("samples/ICMPv6.pcap", tests, t)
}
