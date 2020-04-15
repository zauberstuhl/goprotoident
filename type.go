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

import "github.com/google/gopacket/layers"

const (
  ProtocolICMPv4 Protocol = "ICMPv4"
  ProtocolICMPv6 Protocol = "ICMPv6"
  ProtocolHTTP Protocol = "HTTP"
  ProtocolTLS Protocol = "TLS"
  ProtocolSSL Protocol = "SSL"
  ProtocolSSH Protocol = "SSH"
  ProtocolSMTP Protocol = "SMTP"
  ProtocolDNS Protocol = "DNS"
  ProtocolTCP Protocol = "TCP"
  ProtocolUDP Protocol = "UDP"
  ProtocolUnknown Protocol = "UNKNOWN"
)

type Protocol string

func (protocol Protocol) String() string {
  return string(protocol)
}

type TCPModule interface {
  Match(*layers.TCP) bool
  Protocol() Protocol
}

type TCPModules []TCPModule

type UDPModule interface {
  Match(*layers.UDP) bool
  Protocol() Protocol
}

type UDPModules []UDPModule
