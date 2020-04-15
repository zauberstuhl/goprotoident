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
  "fmt"
  "sync"
  "time"

  "github.com/patrickmn/go-cache"
  "github.com/google/gopacket"
  "github.com/google/gopacket/layers"
)

var (
  tcpModules TCPModules
  udpModules UDPModules

  pkgCache = cache.New(5 * time.Second, 10 * time.Second)
  cacheMutex sync.Mutex
)

func Classify(packet gopacket.Packet) Protocol {
  layer := packet.Layer(layers.LayerTypeTCP)
  if layer != nil {
    tcp := layer.(*layers.TCP)
    if len(tcp.Payload) == 0 {
      return ProtocolTCP
    }

    result := ProtocolUnknown
    for _, module := range tcpModules {
      if module.Match(tcp) {
        result = module.Protocol()
        break
      }
    }

    if result == ProtocolUnknown {
      if cachedResult, ok := pkgCache.Get(fmt.Sprintf("%d", tcp.Seq)); ok {
        result = cachedResult.(Protocol)
      }
    }

    cacheMutex.Lock()
    nextSeq := tcp.Seq + uint32(len(tcp.Payload))
    pkgCache.Set(fmt.Sprintf("%d", nextSeq), result, cache.DefaultExpiration)
    cacheMutex.Unlock()

    return result
  }

  layer = packet.Layer(layers.LayerTypeUDP)
  if layer != nil {
    for _, module := range udpModules {
      udp := layer.(*layers.UDP)
      if len(udp.Payload) == 0 {
        return ProtocolUDP
      }

      if module.Match(udp) {
        return module.Protocol()
      }
    }
  }
  return ProtocolUnknown
}
