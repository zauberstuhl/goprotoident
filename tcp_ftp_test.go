package gpi

import "testing"

func TestTCPFTP(t *testing.T) {
  tests := ProtoTests{
    {Expected: 5, Proto: ProtocolTCP},
    {Expected: 5, Proto: ProtocolFTP},
  }
  testPCAPFile("samples/FTP.pcap", tests, t)
}
