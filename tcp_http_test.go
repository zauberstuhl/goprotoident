package gpi

import "testing"

func TestTCPHTTP(t *testing.T) {
  tests := ProtoTests{
    {Proto: ProtocolHTTP, Expected: 2},
  }
  testPCAPFile("samples/HTTP.pcap", tests, t)
}
