package gpi

import "testing"

func TestICMPv4(t *testing.T) {
  tests := ProtoTests{
    {Expected: 6, Proto: ProtocolICMPv4},
    {Expected: 0, Proto: ProtocolUnknown},
  }
  testPCAPFile("samples/ICMPv4.pcap", tests, t)
}
