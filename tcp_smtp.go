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

type TCPModuleSMTP struct {}

func (module TCPModuleSMTP) Match(tcp *layers.TCP) bool {
  if len(tcp.Payload) < 4 {
    return false
  }

  if !validSMTPPorts(tcp) {
    return false
  }

  if bytes.Equal(tcp.Payload[0:4], []byte("220 ")) {
    return true
  }
  if bytes.Equal(tcp.Payload[0:4], []byte("450 ")) {
    return true
  }
  if bytes.Equal(tcp.Payload[0:4], []byte("550 ")) {
    return true
  }
  if bytes.Equal(tcp.Payload[0:4], []byte("550-")) {
    return true
  }
  if bytes.Equal(tcp.Payload[0:4], []byte("421 ")) {
    return true
  }
  if bytes.Equal(tcp.Payload[0:4], []byte("421-")) {
    return true
  }
  if bytes.Equal(tcp.Payload[0:4], []byte("451 ")) {
    return true
  }
  if bytes.Equal(tcp.Payload[0:4], []byte("451-")) {
    return true
  }
  if bytes.Equal(tcp.Payload[0:4], []byte("452 ")) {
    return true
  }
  if bytes.Equal(tcp.Payload[0:4], []byte("420 ")) {
    return true
  }
  if bytes.Equal(tcp.Payload[0:4], []byte("571 ")) {
    return true
  }
  if bytes.Equal(tcp.Payload[0:4], []byte("553 ")) {
    return true
  }
  if bytes.Equal(tcp.Payload[0:4], []byte("554 ")) {
    return true
  }
  if bytes.Equal(tcp.Payload[0:4], []byte("554-")) {
    return true
  }
  if bytes.Equal(tcp.Payload[0:4], []byte("476 ")) {
    return true
  }
  if bytes.Equal(tcp.Payload[0:4], []byte("475 ")) {
    return true
  }

  if bytes.Equal(tcp.Payload[0:4], []byte("EHLO")) {
    return true
  }
  if bytes.Equal(tcp.Payload[0:4], []byte("ehlo")) {
    return true
  }
  if bytes.Equal(tcp.Payload[0:4], []byte("HELO")) {
    return true
  }
  if bytes.Equal(tcp.Payload[0:4], []byte("helo")) {
    return true
  }
  if bytes.Equal(tcp.Payload[0:4], []byte("NOOP")) {
    return true
  }
  if bytes.Equal(tcp.Payload[0:4], []byte("XXXX")) {
    return true
  }
  if bytes.Equal(tcp.Payload[0:4], []byte("HELP")) {
    return true
  }
  if bytes.Equal(tcp.Payload[0:4], []byte("EXPN")) {
    return true
  }

  if bytes.Equal(tcp.Payload[0:4], []byte("QUIT")) {
    return true
  }
  if bytes.Equal(tcp.Payload[0:4], []byte("quit")) {
    return true
  }
  if bytes.Equal(tcp.Payload[0:4], []byte("Quit")) {
    return true
  }

  return false
}

func (module TCPModuleSMTP) Protocol() Protocol {
  return ProtocolSMTP
}

// init Register and laod the module
func init() {
  tcpModules = append(tcpModules, TCPModuleSMTP{})
}
