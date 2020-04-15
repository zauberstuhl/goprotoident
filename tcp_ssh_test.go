package gpi

import "testing"

func TestTCPSSH(t *testing.T) {
  tests := ProtoTests{
    {Expected: 25, Proto: ProtocolTCP},
    {Expected: 13, Proto: ProtocolSSH},
  }
  testPCAPFile("samples/SSH.pcap", tests, t)
}
