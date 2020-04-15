package gpi

import "testing"

func TestTCPSMTP(t *testing.T) {
  tests := ProtoTests{
    {Expected: 15, Proto: ProtocolTCP},
    {Expected: 13, Proto: ProtocolSMTP},
    {Expected: 0, Proto: ProtocolUnknown},
  }
  testPCAPFile("samples/SMTP.pcap", tests, t)
}
