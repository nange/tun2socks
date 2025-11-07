package engine

import (
    "time"

    "github.com/xjasonlyu/tun2socks/v2/core/adapter"
)

type Key struct {
    MTU                      int           `yaml:"mtu"`
    Mark                     int           `yaml:"fwmark"`
    Proxy                    string        `yaml:"proxy"`
    RestAPI                  string        `yaml:"restapi"`
    Device                   string        `yaml:"device"`
    LogLevel                 string        `yaml:"loglevel"`
    Interface                string        `yaml:"interface"`
    TCPModerateReceiveBuffer bool          `yaml:"tcp-moderate-receive-buffer"`
    TCPSendBufferSize        string        `yaml:"tcp-send-buffer-size"`
    TCPReceiveBufferSize     string        `yaml:"tcp-receive-buffer-size"`
    MulticastGroups          string        `yaml:"multicast-groups"`
    TUNPreUp                 string        `yaml:"tun-pre-up"`
    TUNPostUp                string        `yaml:"tun-post-up"`
    UDPTimeout               time.Duration `yaml:"udp-timeout"`

    // ICMPHandler allows external programs to inject custom ICMP
    // handling logic when using the engine programmatically.
    // It is not intended to be configured via YAML.
    ICMPHandler              adapter.ICMPHandler
}
