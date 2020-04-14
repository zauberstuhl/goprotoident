package gpi

// Network traffic classification library written purely in GoLang
// Copyright (C) 2020  Lukas Matt <lukas@matt.wf>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

import (
  "bytes"

  "github.com/google/gopacket/layers"
)

type TCPModuleSSL struct {}

func (module TCPModuleSSL) Match(tcp *layers.TCP) bool {
  if !validHTTPsPorts(tcp) || len(tcp.Payload) < 4 {
    return false
  }

  // SSLv3
  if bytes.Equal(tcp.Payload[0:3], []byte{0x16, 0x03, 0x00}) {
    return true
  }

  // SSLv2
  if tcp.Payload[0] == 0x80 && bytes.Equal(tcp.Payload[2:4], []byte{0x01, 0x03}) {
    return true
  }
  if tcp.Payload[0] == 0x81 && bytes.Equal(tcp.Payload[2:4], []byte{0x01, 0x03}) {
    return true
  }
  return false
}

func (module TCPModuleSSL) Protocol() Protocol {
  return ProtocolSSL
}

// init Register and laod the module
func init() {
  tcpModules = append(tcpModules, TCPModuleSSL{})
}
