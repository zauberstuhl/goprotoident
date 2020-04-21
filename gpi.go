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

// ClassifyByPorts will return protocol associated by the standard
// port mapping. This can be seen as fallback option in case e.g.
// the packet inspection of Classify returns ProtocolUnknown.
func ClassifyByPorts(packet gopacket.Packet) Protocol {
  layer := packet.Layer(layers.LayerTypeTCP)
  if layer != nil {
    tcp := layer.(*layers.TCP)
    if protocol, ok := tcpPorts[tcp.DstPort]; ok {
      return protocol
    }
    if protocol, ok := tcpPorts[tcp.SrcPort]; ok {
      return protocol
    }
    return ProtocolTCP
  }

  layer = packet.Layer(layers.LayerTypeUDP)
  if layer != nil {
    udp := layer.(*layers.UDP)
    if protocol, ok := udpPorts[udp.SrcPort]; ok {
      return protocol
    }
    if protocol, ok := udpPorts[udp.DstPort]; ok {
      return protocol
    }
    return ProtocolUDP
  }
  return ProtocolUnknown
}

// Classify tries to identify network traffic by doing spot
// checks of the provided packet. The function will cache
// certain packages to improve detection rate
func Classify(packet gopacket.Packet) Protocol {
  layer := packet.Layer(layers.LayerTypeICMPv4)
  if layer != nil {
    return ProtocolICMPv4
  }

  layer = packet.Layer(layers.LayerTypeICMPv6)
  if layer != nil {
    return ProtocolICMPv6
  }

  layer = packet.Layer(layers.LayerTypeTCP)
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
      } else {
        result = ProtocolTCP
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
    udp := layer.(*layers.UDP)
    if len(udp.Payload) == 0 {
      return ProtocolUDP
    }

    for _, module := range udpModules {
      if module.Match(udp) {
        return module.Protocol()
      }
    }
    return ProtocolUDP
  }
  return ProtocolUnknown
}
