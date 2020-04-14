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

type TCPModuleHTTP struct {}

func (module TCPModuleHTTP) Match(tcp *layers.TCP) bool {
  if !validHTTPPorts(tcp) {
    return false
  }

  if validHTTPResponse(tcp) {
    return true
  }

  if validHTTPRequest(tcp) {
    return true
  }

  return false
}

func (module TCPModuleHTTP) Protocol() Protocol {
  return ProtocolHTTP
}

func validHTTPResponse(tcp *layers.TCP) bool {
  if len(tcp.Payload) == 0 {
    return true
  }

  if len(tcp.Payload) > 4 {
    return bytes.Equal(tcp.Payload[0:4], []byte("HTTP"))
  }

  // e.g. mini_httpd
  if len(tcp.Payload) > 4 {
    return bytes.Equal(tcp.Payload[0:4], []byte("UNKN"))
  }

  return false
}

func validHTTPRequest(tcp *layers.TCP) bool {
  var methods = []string{
    // HTTP methods
    "GET",
    "HEAD",
    "POST",
    "PUT",
    "DELETE",
    "CONNECT",
    "OPTIONS",
    "TRACE",
    "PATCH",
    // SVN
    "REPO",
    // WebDAV
    "LOCK",
    "UNLO",
    "OPTI",
    "PROP",
    "MKCO",
    "POLL",
    "SEAR",
    // Ntrip
    "SOUR",
  }

  for _, methodString := range methods {
    var method = []byte(methodString)
    // every method should be followed by a blank
    method = append(method, 0x20)

    var methodLen = len(method)
    if len(tcp.Payload) >= methodLen && bytes.Equal(tcp.Payload[0:methodLen], method) {
      return true
    }
  }
  return false
}

func validHTTPPorts(tcp *layers.TCP) bool {
  return tcp.SrcPort == 80 || tcp.DstPort == 80 ||
    tcp.SrcPort == 8080 || tcp.DstPort == 8080 ||
    tcp.SrcPort == 8081 || tcp.DstPort == 8081
}

// init Register and laod the module
func init() {
  tcpModules = append(tcpModules, TCPModuleHTTP{})
}
