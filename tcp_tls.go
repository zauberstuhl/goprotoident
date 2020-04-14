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

type TCPModuleTLS struct {}

func (module TCPModuleTLS) Match(tcp *layers.TCP) bool {
  if !validHTTPsPorts(tcp) || len(tcp.Payload) < 4 {
    return false
  }

  if bytes.Equal(tcp.Payload[0:4], []byte{0x16, 0x00, 0x00, 0x00}) {
    return true
  }

  // TLS
  if bytes.Equal(tcp.Payload[0:3], []byte{0x16, 0x03, 0x01}) {
    return true
  }
  if bytes.Equal(tcp.Payload[0:3], []byte{0x16, 0x03, 0x02}) {
    return true
  }
  if bytes.Equal(tcp.Payload[0:3], []byte{0x16, 0x03, 0x03}) {
    return true
  }

  // TLS Alerts
  if bytes.Equal(tcp.Payload[0:3], []byte{0x15, 0x03, 0x01}) {
    return true
  }
  if bytes.Equal(tcp.Payload[0:3], []byte{0x15, 0x03, 0x02}) {
    return true
  }
  if bytes.Equal(tcp.Payload[0:3], []byte{0x15, 0x03, 0x03}) {
    return true
  }
  if bytes.Equal(tcp.Payload[0:3], []byte{0x16, 0x03, 0x00}) {
    return true
  }

  // TLS Change
  if bytes.Equal(tcp.Payload[0:3], []byte{0x17, 0x03, 0x01}) {
    return true
  }
  if bytes.Equal(tcp.Payload[0:3], []byte{0x17, 0x03, 0x02}) {
    return true
  }
  if bytes.Equal(tcp.Payload[0:3], []byte{0x17, 0x03, 0x03}) {
    return true
  }

  // TLS Content
  if bytes.Equal(tcp.Payload[0:3], []byte{0x14, 0x03, 0x01}) {
    return true
  }
  if bytes.Equal(tcp.Payload[0:3], []byte{0x14, 0x03, 0x02}) {
    return true
  }
  if bytes.Equal(tcp.Payload[0:3], []byte{0x14, 0x03, 0x03}) {
    return true
  }
  return false
}

func (module TCPModuleTLS) Protocol() Protocol {
  return ProtocolTLS
}

// init Register and laod the module
func init() {
  tcpModules = append(tcpModules, TCPModuleTLS{})
}
