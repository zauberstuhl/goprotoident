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

func validSMTPPorts(tcp *layers.TCP) bool {
  return tcp.SrcPort == 25 || tcp.DstPort == 25 ||
    tcp.SrcPort == 465 || tcp.DstPort == 465 ||
    tcp.SrcPort == 587 || tcp.DstPort == 587 ||
    tcp.SrcPort == 2525 || tcp.DstPort == 2525
}
