#!/usr/bin/env python3
import argparse
from subprocess import run

bridges = ['br1', 'br2', 'br3']
namespaces = {
        'c1' : {'interfaces' :
                    [{'ns':'veth1',
                      'host':'br-veth1',
                      'bridge':'br1',
                      'ip':'10.100.0.1/24'}
                    ],
                 'exec' : 
                    ['ip r add default via 10.100.0.254 dev veth1']
                 },
        'c2' : {'interfaces' :
                    [{'ns':'veth2',
                      'host':'br-veth2',
                      'bridge':'br1',
                      'ip':'10.100.0.2/24'}
                    ],
                 'exec' : 
                    ['ip r add default via 10.100.0.254 dev veth2']
                },
        'classifier' : {'interfaces' :
                    [{'ns':'veth3',
                      'host':'br-veth3',
                      'bridge':'br1',
                      'ip':'10.100.0.254/24'},
                     {'ns':'veth4',
                      'host':'br-veth4',
                      'bridge':'br2',
                      'ip':'10.200.0.254/24'}
                    ],
                 'exec' : 
                    ['sysctl -w net.mpls.platform_labels=1048575',
                     'sudo sysctl -w net.mpls.conf.lo.input=1',
                     'sudo sysctl -w net.mpls.conf.veth4.input=1',
                     'ip a add 10.200.0.253/24 dev veth4',
                     'ip rule add from 10.200.0.254/32 table forward',
                     'ip rule add from 10.200.0.253/32 table dpi',
                     'ip r add table forward 10.201.0.100/32 encap mpls 111/200 via inet 10.200.0.1',
                     'ip r add table dpi 10.201.0.100/32 encap mpls 112/111/200 via inet 10.200.0.2 dev veth4',
                     '/var/local/poc-classification/haproxy.sh',
                     'ip xfrm policy add src 10.200.0.254 dst 10.201.0.100 dir out tmpl src 10.200.0.254 dst 10.201.0.100 proto esp mode tunnel reqid 0x11111111',
                     'ip xfrm state add src 10.200.0.254 dst 10.201.0.100 spi 0x11111111 proto esp mode tunnel aead "rfc4106(gcm(aes))" 0x1234567890ABCDEF1234567890abcdef12345678 128 reqid 0x11111111',
                     'ip xfrm policy add src 10.200.0.253 dst 10.201.0.100 dir out tmpl src 10.200.0.253 dst 10.201.0.100 proto esp mode tunnel reqid 0x11111112',
                     'ip xfrm state add src 10.200.0.253 dst 10.201.0.100 spi 0x11111112 proto esp mode tunnel aead "rfc4106(gcm(aes))" 0x1234567890ABCDEF1234567890abcdef12345678 128 reqid 0x11111112'
                     ]
                },
        'vf1' : {'interfaces' :
                    [{'ns':'veth5',
                      'host':'br-veth5',
                      'bridge':'br2',
                      'ip':'10.200.0.1/24'},
                     {'ns':'veth6',
                      'host':'br-veth6',
                      'bridge':'br3',
                      'ip':'10.201.0.1/24'}
                    ],
                 'exec' : 
                    ['sysctl -w net.mpls.platform_labels=1048575',
                     'ip r add 10.100.0.0/24 via 10.200.0.254 dev veth5',
                     'sudo sysctl -w net.mpls.conf.lo.input=1',
                     'sudo sysctl -w net.mpls.conf.veth5.input=1',
                     'sudo sysctl -w net.mpls.conf.veth6.input=1',
                     'ip -f mpls route add 111 dev lo',
                     'ip -f mpls route add 200 as 200 via inet 10.201.0.100']
                },
        'vf2' : {'interfaces' :
                    [{'ns':'veth7',
                      'host':'br-veth7',
                      'bridge':'br2',
                      'ip':'10.200.0.2/24'},
                     {'ns':'veth8',
                      'host':'br-veth8',
                      'bridge':'br3',
                      'ip':'10.201.0.2/24'}
                    ],
                 'exec' : 
                    ['sysctl -w net.mpls.platform_labels=1048575',
                     'ip l add proxyIn_1 type veth peer name proxyIn_2',
                     'ip l s proxyIn_1 up',
                     'ip l s proxyIn_2 up',
                     'ip r add 10.100.0.0/24 via 10.200.0.254 dev veth7',
                     'sudo sysctl -w net.mpls.conf.lo.input=1',
                     'sudo sysctl -w net.mpls.conf.veth7.input=1',
                     'sudo sysctl -w net.mpls.conf.veth8.input=1',
                     'iptables -A FORWARD -m string --algo kmp --string test -j DROP',
                     'ip -f mpls route add 112 dev proxyIn_1',
                     'ip -f mpls route add 111 as 111 via inet 10.200.0.1',
                     'ip -f mpls route add 200 as 200 via inet 10.201.0.100',
                     '/var/local/poc-classification/proxy.sh > /dev/null &',
                     'ethtool -K veth7 rx off tx off',
                     'ethtool -K veth8 rx off tx off']
                },
        's1' : {'interfaces' :
                    [{'ns':'veth9',
                      'host':'br-veth9',
                      'bridge':'br3',
                      'ip':'10.201.0.100/24'}
                    ],
                 'exec' : 
                    ['sysctl -w net.mpls.platform_labels=1048575',
                     'ip r add default via 10.201.0.1 dev veth9',
                     'sudo sysctl -w net.mpls.conf.lo.input=1',
                     'sudo sysctl -w net.mpls.conf.veth9.input=1',
                     'ip r add 10.200.0.253/32 via 10.201.0.2 dev veth9',
                     'ip -f mpls route add 200 dev lo',
                     '/var/local/poc-classification/http.sh',
                     'ip xfrm policy add src 10.200.0.254 dst 10.201.0.100 dir in tmpl src 10.200.0.254 dst 10.201.0.100 proto esp mode tunnel reqid 0x11111111',
                     'ip xfrm state add src 10.200.0.254 dst 10.201.0.100 spi 0x11111111 proto esp mode tunnel aead "rfc4106(gcm(aes))" 0x1234567890ABCDEF1234567890abcdef12345678 128 reqid 0x11111111',
                     'ip xfrm policy add src 10.200.0.253 dst 10.201.0.100 dir in tmpl src 10.200.0.253 dst 10.201.0.100 proto esp mode tunnel reqid 0x11111112',
                     'ip xfrm state add src 10.200.0.253 dst 10.201.0.100 spi 0x11111112 proto esp mode tunnel aead "rfc4106(gcm(aes))" 0x1234567890ABCDEF1234567890abcdef12345678 128 reqid 0x11111112'
                     ]
                }
        }

parser = argparse.ArgumentParser(description='Proof of concept for classification.')
parser.add_argument('--start', dest='start', action='store_true',
                    help='start the poc)')
parser.add_argument('--c1', dest='shell', action='store_const', const='c1',
                    help='start shell on given host')
parser.add_argument('--c2', dest='shell', action='store_const', const='c2',
                    help='start shell on given host')
args = parser.parse_args()

if args.start:
    run(['sysctl', '-w', 'net.ipv4.ip_forward=1'])
    run(['modprobe', 'mpls_router'])
    for bridge in bridges:
        run(['ip', 'link', 'add', 'name', bridge, 'type', 'bridge'])
        run(['ip', 'link', 'set', bridge, 'up'])
    for ns, config in namespaces.items():
        print('NS ' + ns)
        run(['ip', 'netns', 'add', ns])
        run(['ip', 'netns', 'exec', ns, 'ip', 'link', 'set', 'lo', 'up'])
        for interface in config['interfaces']:
            print(' interface: ' + interface['ns'])
            run(['ip', 'link', 'add', interface['ns'], 'type', 'veth', 'peer', 'name', interface['host']])
            run(['ip', 'link', 'set', interface['ns'], 'netns', ns])
            run(['ip', 'netns', 'exec', ns, 'ip', 'addr', 'add', interface['ip'], 'dev', interface['ns']])
            run(['ip', 'netns', 'exec', ns, 'ip', 'link', 'set', interface['ns'], 'up'])
            run(['ip', 'link', 'set', interface['host'], 'up'])
            run(['ip', 'link', 'set', interface['host'], 'master', interface['bridge']])
        for cmd in config['exec']:
            print(' exec: ' + cmd)
            run('ip netns exec ' + ns + ' ' + cmd, shell=True)

elif args.shell:
    run(['ip', 'netns', 'exec', args.shell, 'bash'])
