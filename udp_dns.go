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

type UDPModuleDNS struct {}

func (module UDPModuleDNS) Match(udp *layers.UDP) bool {
  if udp.SrcPort != 53 && udp.DstPort != 53 {
    return false
  }

  flags := udp.Payload[2:4] // 16 bit DNS flags
  qr := int(flags[0] >> 7)
  opcode := int(flags[0] << 1 >> 4)
  // lets skip to the end
  rcode := int(flags[1] >> 4)

  // NOTE in theory rcode can be greater then 23 it is just unassigned currently
  // https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
  return (qr == 0 || qr == 1) &&
    (opcode == 0 || opcode == 1 || opcode == 2) &&
    rcode >= 0 && rcode <= 23
}

func (module UDPModuleDNS) Protocol() Protocol {
  return ProtocolDNS
}

// init Register and laod the module
func init() {
  udpModules = append(udpModules, UDPModuleDNS{})
}
