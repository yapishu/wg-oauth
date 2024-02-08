package wgapi

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"wg-oauth/logger"

	"github.com/google/nftables"
	"github.com/sbezverk/nftableslib"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	localSubnet = os.Getenv("LOCAL_SUBNET") // eg "10.10.0.0/16"
	gatewayIP   = os.Getenv("GATEWAY_IP")   // eg "10.10.110.1"
	IfaceName   = "wg0"
)

type FwExemption struct {
	IP       string
	Port     string
	Protocol string
}

type WireGuardManager struct {
	wgClient     *wgctrl.Client
	device       string
	mu           sync.Mutex
	peerIPMap    map[string]string
	fwExemptions []FwExemption
	localSubnet  string
	gatewayIP    string
	nfConn       *nftables.Conn
}

func init() {
	configPath := fmt.Sprintf("/etc/wireguard/%s.conf", IfaceName)
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		logger.Logger.Info(fmt.Sprintf("Configuration for %s does not exist, creating...", IfaceName))
		privateKey, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			logger.Logger.Info(fmt.Sprintf("Failed to generate private key: %v\n", err))
			return
		}
		publicKey := privateKey.PublicKey()
		config := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.10.130.1/24\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.10.130.1/32\n", privateKey.String(), publicKey.String())
		if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
			logger.Logger.Error(fmt.Sprintf("Failed to write WireGuard configuration: %v", err))
			return
		}
		logger.Logger.Info(fmt.Sprintf("Configuration for %s created at %s", IfaceName, configPath))
	} else if err != nil {
		logger.Logger.Error(fmt.Sprintf("Failed to check if configuration exists: %v", err))
		return
	} else {
		logger.Logger.Info(fmt.Sprintf("Configuration for %s already exists.", IfaceName))
	}
	cmd := exec.Command("wg-quick", "up", IfaceName)
	if err := cmd.Run(); err != nil {
		logger.Logger.Error(fmt.Sprintf("Failed to bring up WireGuard interface %s (may already be up)", IfaceName))
		return
	}
	logger.Logger.Info(fmt.Sprintf("WireGuard interface %s is up", IfaceName))
}

func NewWireGuardManager(device string) (*WireGuardManager, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create wgctrl client: %w", err)
	}
	fwAllow := parseExemptions(os.Getenv("FW_EXEMPTIONS"))
	// eg "192.168.0.3:53,192.168.0.4:80/tcp"
	manager := &WireGuardManager{
		wgClient:     client,
		device:       device,
		peerIPMap:    make(map[string]string),
		fwExemptions: fwAllow,
		localSubnet:  localSubnet,
		gatewayIP:    gatewayIP,
	}
	if err := manager.initNftables(); err != nil {
		return nil, err
	}
	return manager, nil
}

func (m *WireGuardManager) initNftables() error {
	conn := nftableslib.InitConn()
	m.nfConn = conn
	logger.Logger.Info("Ensuring wgchain exists in wgtable")
	ti := nftableslib.InitNFTables(m.nfConn)
	tableFamily := nftables.TableFamilyIPv4
	_, err := ti.Tables().Table("wgtable", tableFamily)
	if err != nil {
		if err := ti.Tables().CreateImm("wgtable", tableFamily); err != nil {
			return fmt.Errorf("failed to create wgtable: %v", err)
		}
		logger.Logger.Info("wgtable created successfully")
	}
	ci, err := ti.Tables().Table("wgtable", tableFamily)
	if err != nil {
		return fmt.Errorf("failed to get table interface for wgtable: %v", err)
	}
	if !ci.Chains().Exist("wgchain") {
		policy := nftableslib.ChainPolicyAccept
		attrs := &nftableslib.ChainAttributes{
			Type:     nftables.ChainTypeFilter,
			Hook:     nftables.ChainHookPrerouting,
			Priority: nftables.ChainPriorityFilter,
			Policy:   &policy,
		}
		if err := ci.Chains().CreateImm("wgchain", attrs); err != nil {
			return fmt.Errorf("failed to create wgchain in wgtable: %v", err)
		}
		logger.Logger.Info("wgchain created successfully in wgtable")
	} else {
		logger.Logger.Info("wgchain already exists in wgtable")
	}
	if err := m.nfConn.Flush(); err != nil {
		return fmt.Errorf("failed to flush nftables state after ensuring wgchain exists: %v", err)
	}
	return nil
}

// dynamically allow or block a peer's access to the lan subnet
func (m *WireGuardManager) UpdatePeerRules(peerPublicKey string, allowAccess bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	peerKey, err := wgtypes.ParseKey(peerPublicKey)
	if err != nil {
		return fmt.Errorf("invalid peer public key: %w", err)
	}
	device, err := m.wgClient.Device(m.device)
	if err != nil {
		return fmt.Errorf("failed to get WireGuard device configuration: %w: please make sure you have permission", err)
	}
	found := false
	for _, peer := range device.Peers {
		if peer.PublicKey == peerKey {
			found = true
			break
		}
	}
	if !found {
		return errors.New("peer public key not found")
	}
	if allowAccess {
		// allow traffic
		if err := m.allowPeerTraffic(peerPublicKey); err != nil {
			return fmt.Errorf("failed to allow traffic for peer: %w", err)
		}
	} else {
		// block traffic except DNS
		if err := m.blockPeerTrafficExcept(peerPublicKey); err != nil {
			return fmt.Errorf("failed to block traffic for peer: %w", err)
		}
	}
	return nil
}

func (m *WireGuardManager) findPeerAllowedIPs(peerPublicKey string) ([]string, error) {
	device, err := m.wgClient.Device(m.device)
	if err != nil {
		return nil, fmt.Errorf("failed to get WireGuard device configuration: %w", err)
	}
	for _, peer := range device.Peers {
		if peer.PublicKey.String() == peerPublicKey {
			allowedIPs := make([]string, len(peer.AllowedIPs))
			for i, ip := range peer.AllowedIPs {
				allowedIPs[i] = ip.String()
			}
			logger.Logger.Info(fmt.Sprintf("Allowed IPs: %v", allowedIPs))
			return allowedIPs, nil
		}
	}
	return nil, fmt.Errorf("peer public key %s not found", peerPublicKey)
}

func (m *WireGuardManager) allowPeerTraffic(peerPublicKey string) error {
	logger.Logger.Info(fmt.Sprintf("Allowing LAN traffic for %s", peerPublicKey))
	peerKey, err := wgtypes.ParseKey(peerPublicKey)
	if err != nil {
		return fmt.Errorf("invalid peer public key: %w", err)
	}
	device, err := m.wgClient.Device(m.device)
	if err != nil {
		return fmt.Errorf("failed to get WireGuard device configuration: %w", err)
	}
	var currentPeerIP string
	found := false
	for _, peer := range device.Peers {
		if peer.PublicKey == peerKey {
			found = true
			if peer.Endpoint != nil {
				currentPeerIP = peer.Endpoint.IP.String()
			}
			break
		}
	}
	if !found {
		return errors.New("peer public key not found")
	}
	if currentPeerIP == "" {
		// return errors.New("current peer IP not found or peer has not established a connection")
		currentPeerIP = "13.13.13.13"
	}
	allowedIPs := []net.IPNet{
		{
			IP:   net.ParseIP(currentPeerIP),
			Mask: net.CIDRMask(32, 32),
		},
	}
	err = m.wgClient.ConfigureDevice(m.device, wgtypes.Config{
		ReplacePeers: false,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey:         peerKey,
				UpdateOnly:        true,
				ReplaceAllowedIPs: true,
				AllowedIPs:        allowedIPs,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to update peer allowed IPs: %w", err)
	}
	for _, peerIP := range allowedIPs {
		if err := m.addRule(peerIP.String(), m.localSubnet, "accept", m.fwExemptions, fmt.Sprintf("peer:%s", peerPublicKey)); err != nil {
			return fmt.Errorf("failed to allow traffic for peer %s: %w", peerPublicKey, err)
		}
	}
	return nil
}

func (m *WireGuardManager) blockPeerTrafficExcept(peerPublicKey string) error {
	logger.Logger.Info(fmt.Sprintf("Blocking nonexempt traffic for %s", peerPublicKey))
	allowedIPs, err := m.findPeerAllowedIPs(peerPublicKey)
	if err != nil {
		return err
	}
	for _, peerIP := range allowedIPs {
		if err := m.addRule(peerIP, m.localSubnet, "drop", []FwExemption{}, fmt.Sprintf("block all: peer %s", peerPublicKey)); err != nil {
			return fmt.Errorf("failed to block traffic for peer %s: %w", peerPublicKey, err)
		}
		for _, server := range m.fwExemptions {
			if err := m.addRule(peerIP, server.IP, "accept", []FwExemption{server}, fmt.Sprintf("allow: peer %s to %s:%s/%s", peerPublicKey, server.IP, server.Port, server.Protocol)); err != nil {
				return fmt.Errorf("failed to allow traffic for peer %s to server %s: %w", peerPublicKey, server.IP, err)
			}
		}
	}
	return nil
}

func (m *WireGuardManager) allowInternetAccess(peerPublicKey string) error {
	allowedIPs, err := m.findPeerAllowedIPs(peerPublicKey)
	if err != nil {
		return err
	}
	for _, peerIP := range allowedIPs {
		if err := m.addRule(peerIP, m.gatewayIP, "accept", m.fwExemptions, fmt.Sprintf("peer:%s", peerPublicKey)); err != nil {
			return fmt.Errorf("failed to allow internet access for peer %s: %w", peerPublicKey, err)
		}
	}
	return nil
}

func (m *WireGuardManager) RestartWireGuardInterface() error {
	downCmd := exec.Command("wg-quick", "down", m.device)
	if err := downCmd.Run(); err != nil {
		logger.Logger.Error(fmt.Sprintf("Failed to bring down WireGuard interface %s: %v", m.device, err))
		return fmt.Errorf("failed to bring down WireGuard interface %s: %w", m.device, err)
	}
	upCmd := exec.Command("wg-quick", "up", m.device)
	if err := upCmd.Run(); err != nil {
		logger.Logger.Error(fmt.Sprintf("Failed to bring up WireGuard interface %s: %v", m.device, err))
		return fmt.Errorf("failed to bring up WireGuard interface %s: %w", m.device, err)
	}
	logger.Logger.Info(fmt.Sprintf("WireGuard interface %s restarted successfully", m.device))
	return nil
}

func (m *WireGuardManager) addRule(srcIP, destIP, action string, fwExemptions []FwExemption, comment string) error {
	logger.Logger.Info(fmt.Sprintf("Adding rule: %v->%v/%v for %v", srcIP, destIP, action, comment))
	ti := nftableslib.InitNFTables(m.nfConn)
	tableFamily := nftables.TableFamilyIPv4
	if err := ti.Tables().Create("wgtable", tableFamily); err != nil && !strings.Contains(err.Error(), "exists") {
		return fmt.Errorf("failed to create/find table: %v", err)
	}
	ci, err := ti.Tables().Table("wgtable", tableFamily)
	if err != nil {
		return fmt.Errorf("failed to get table interface: %v", err)
	}
	userDataBytes := []byte(comment)
	srcAddr, err := nftableslib.NewIPAddr(srcIP)
	if err != nil {
		return fmt.Errorf("failed to parse source IP address: %v", err)
	}
	destAddr, err := nftableslib.NewIPAddr(destIP)
	if err != nil {
		return fmt.Errorf("failed to parse destination IP address: %v", err)
	}
	ruleAction, err := translateActionToVerdict(action)
	if err != nil {
		return fmt.Errorf("failed to parse rule verdict: %v", err)
	}
	rule := &nftableslib.Rule{
		L3: &nftableslib.L3Rule{
			Src: &nftableslib.IPAddrSpec{
				List: []*nftableslib.IPAddr{srcAddr},
			},
			Dst: &nftableslib.IPAddrSpec{
				List: []*nftableslib.IPAddr{destAddr},
			},
		},
		Action:   ruleAction,
		UserData: userDataBytes,
	}
	for _, exemption := range fwExemptions {
		l4Rule, err := protocolPortExpr(exemption.Protocol, exemption.Port)
		if err != nil {
			return fmt.Errorf("failed to create protocol/port expression: %v", err)
		}
		rule.L4 = l4Rule
	}
	ri, err := ci.Chains().Chain("wgchain")
	if err != nil {
		return fmt.Errorf("failed to get chain interface: %v", err)
	}
	if _, err := ri.Rules().Create(rule); err != nil {
		return fmt.Errorf("failed to create rule: %v", err)
	}
	if err := m.nfConn.Flush(); err != nil {
		return fmt.Errorf("failed to program nftable with error: %+v", err)
	}
	return nil
}

func (m *WireGuardManager) ExpiredRuleCleanup(peerPublicKey string) {
	logger.Logger.Info(fmt.Sprintf("Removing expired rules for %s", peerPublicKey))
	identifier := []byte(fmt.Sprintf("peer:%v", peerPublicKey))
	conn := nftableslib.InitConn()
	ti := nftableslib.InitNFTables(conn)
	tables, err := ti.Tables().Get(nftables.TableFamilyIPv4)
	if err != nil {
		logger.Logger.Error(fmt.Sprintf("Error getting tables: %v", err))
		return
	}
	for _, tableName := range tables {
		chainsInterface, err := ti.Tables().Table(tableName, nftables.TableFamilyIPv4)
		if err != nil {
			logger.Logger.Error(fmt.Sprintf("Error getting chains for table %s: %v", tableName, err))
			continue
		}
		chainNames, err := chainsInterface.Chains().Get()
		if err != nil {
			logger.Logger.Error(fmt.Sprintf("Error getting chain names for table %s: %v", tableName, err))
			continue
		}
		for _, chainName := range chainNames {
			rulesInterface, err := chainsInterface.Chains().Chain(chainName)
			if err != nil {
				logger.Logger.Error(fmt.Sprintf("Error getting rules interface for chain %s: %v", chainName, err))
				continue
			}
			rulesUserData, err := rulesInterface.Rules().GetRulesUserData()
			if err != nil {
				logger.Logger.Error(fmt.Sprintf("Error getting rules user data for chain %s: %v", chainName, err))
				continue
			}
			for ruleHandle, userData := range rulesUserData {
				if len(userData) >= len(identifier) && bytes.Contains(userData, identifier) {
					if err := rulesInterface.Rules().DeleteImm(ruleHandle); err != nil {
						logger.Logger.Error(fmt.Sprintf("Failed to delete rule with handle %d: %v", ruleHandle, err))
					} else {
						logger.Logger.Info(fmt.Sprintf("Deleted rule with handle %d in chain %s", ruleHandle, chainName))
					}
				}
			}
		}
	}
}

func (m *WireGuardManager) AddPeer(peerConfig wgtypes.PeerConfig) error {
	logger.Logger.Info(fmt.Sprintf("Adding peer %v", peerConfig.PublicKey))
	m.mu.Lock()
	defer m.mu.Unlock()
	err := m.wgClient.ConfigureDevice(m.device, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerConfig},
	})
	if err != nil {
		return fmt.Errorf("failed to add peer: %w", err)
	}
	return m.persistConfiguration()
}

func (m *WireGuardManager) RemovePeer(publicKey wgtypes.Key) error {
	logger.Logger.Info(fmt.Sprintf("Removing peer %v", publicKey))
	m.mu.Lock()
	defer m.mu.Unlock()
	err := m.wgClient.ConfigureDevice(m.device, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey: publicKey,
				Remove:    true,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to remove peer: %w", err)
	}
	return m.persistConfiguration()
}

func (m *WireGuardManager) persistConfiguration() error {
	device, err := m.wgClient.Device(m.device)
	if err != nil {
		return fmt.Errorf("failed to fetch current WireGuard configuration: %w", err)
	}
	configContent, err := exportConfig(device)
	if err != nil {
		return fmt.Errorf("failed to export configuration: %w", err)
	}
	configPath := fmt.Sprintf("/etc/wireguard/%s.conf", m.device)
	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		return fmt.Errorf("failed to write WireGuard configuration to file: %w", err)
	}
	return m.RestartWireGuardInterface()
}

func exportConfig(device *wgtypes.Device) (string, error) {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	b.WriteString(fmt.Sprintf("PrivateKey = %s\n", device.PrivateKey.String()))
	if device.ListenPort != 0 {
		b.WriteString(fmt.Sprintf("ListenPort = %d\n", device.ListenPort))
	}
	if device.FirewallMark != 0 {
		b.WriteString(fmt.Sprintf("FwMark = %d\n", device.FirewallMark))
	}
	for _, peer := range device.Peers {
		b.WriteString("\n[Peer]\n")
		b.WriteString(fmt.Sprintf("PublicKey = %s\n", peer.PublicKey.String()))
		if peer.PresharedKey != (wgtypes.Key{}) {
			b.WriteString(fmt.Sprintf("PresharedKey = %s\n", peer.PresharedKey.String()))
		}
		if len(peer.AllowedIPs) > 0 {
			allowedIPs := make([]string, len(peer.AllowedIPs))
			for i, ipNet := range peer.AllowedIPs {
				allowedIPs[i] = ipNet.String()
			}
			b.WriteString(fmt.Sprintf("AllowedIPs = %s\n", strings.Join(allowedIPs, ", ")))
		}
		if peer.Endpoint != nil {
			b.WriteString(fmt.Sprintf("Endpoint = %s\n", peer.Endpoint.String()))
		}
		if peer.PersistentKeepaliveInterval != 0 {
			b.WriteString(fmt.Sprintf("PersistentKeepalive = %d\n", int(peer.PersistentKeepaliveInterval.Seconds())))
		}
	}
	return b.String(), nil
}

func protocolPortExpr(protocol, port string) (*nftableslib.L4Rule, error) {
	protoNum, err := protocolToNumber(protocol)
	if err != nil {
		return nil, err
	}
	portNum, err := strconv.Atoi(port)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %v", err)
	}
	l4Rule := &nftableslib.L4Rule{
		L4Proto: protoNum,
		Dst: &nftableslib.Port{
			List:  nftableslib.SetPortList([]int{portNum}),
			RelOp: nftableslib.EQ,
		},
	}
	return l4Rule, nil
}

func protocolToNumber(protocol string) (byte, error) {
	switch protocol {
	case "tcp":
		return 6, nil
	case "udp":
		return 17, nil
	default:
		return 0, fmt.Errorf("unsupported protocol: %s", protocol)
	}
}

func translateActionToVerdict(action string) (*nftableslib.RuleAction, error) {
	var key int
	switch action {
	case "accept":
		key = nftableslib.NFT_ACCEPT
	case "drop":
		key = nftableslib.NFT_DROP
	default:
		return nil, fmt.Errorf("unsupported action: %s", action)
	}
	return nftableslib.SetVerdict(key)
}

func parseExemptions(envVar string) []FwExemption {
	var servers []FwExemption
	if envVar != "" {
		for _, item := range strings.Split(envVar, ",") {
			parts := strings.Split(item, ":")
			if len(parts) != 2 {
				logger.Logger.Warn(fmt.Sprintf("Malformed firewall allow rule (missing port): %s", item))
				continue
			}
			ip := parts[0]
			portProtocol := strings.Split(parts[1], "/")
			if len(portProtocol) != 2 {
				logger.Logger.Warn(fmt.Sprintf("Malformed firewall allow rule (missing protocol): %s", item))
				continue
			}
			port := portProtocol[0]
			protocol := portProtocol[1]
			servers = append(servers, FwExemption{
				IP:       ip,
				Port:     port,
				Protocol: protocol,
			})
		}
	}
	return servers
}
