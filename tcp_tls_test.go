package gpi

import "testing"

func TestTCPTLS(t *testing.T) {
  tests := ProtoTests{
    {Expected: 26, Proto: ProtocolTCP},
    {Expected: 24, Proto: ProtocolTLS},
  }
  testPCAPFile("samples/TLS.pcap", tests, t)
}
