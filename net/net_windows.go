// +build windows

package net

import (
	"errors"
	"net"
	"os"

	"github.com/shirou/gopsutil/internal/common"
	"golang.org/x/sys/windows"
	"os/exec"
	"strings"
	"strconv"
)

var (
	modiphlpapi             = windows.NewLazyDLL("iphlpapi.dll")
	procGetExtendedTCPTable = modiphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUDPTable = modiphlpapi.NewProc("GetExtendedUdpTable")
)

const (
	TCPTableBasicListener = iota
	TCPTableBasicConnections
	TCPTableBasicAll
	TCPTableOwnerPIDListener
	TCPTableOwnerPIDConnections
	TCPTableOwnerPIDAll
	TCPTableOwnerModuleListener
	TCPTableOwnerModuleConnections
	TCPTableOwnerModuleAll
)

func IOCounters(pernic bool) ([]IOCountersStat, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var ret []IOCountersStat

	for _, ifi := range ifs {
		c := IOCountersStat{
			Name: ifi.Name,
		}

		row := windows.MibIfRow{Index: uint32(ifi.Index)}
		e := windows.GetIfEntry(&row)
		if e != nil {
			return nil, os.NewSyscallError("GetIfEntry", e)
		}
		c.BytesSent = uint64(row.OutOctets)
		c.BytesRecv = uint64(row.InOctets)
		c.PacketsSent = uint64(row.OutUcastPkts)
		c.PacketsRecv = uint64(row.InUcastPkts)
		c.Errin = uint64(row.InErrors)
		c.Errout = uint64(row.OutErrors)
		c.Dropin = uint64(row.InDiscards)
		c.Dropout = uint64(row.OutDiscards)

		ret = append(ret, c)
	}

	if pernic == false {
		return getIOCountersAll(ret)
	}
	return ret, nil
}

// NetIOCountersByFile is an method which is added just a compatibility for linux.
func IOCountersByFile(pernic bool, filename string) ([]IOCountersStat, error) {
	return IOCounters(pernic)
}

// Return a list of network connections opened by a process
func Connections(kind string) ([]ConnectionStat, error) {
	connections, err := ParseNetstat()
	return connections, err
}

// Return a list of network connections opened by a process.
func ConnectionsPid(kind string, pid int32) ([]ConnectionStat, error) {
	//ParseNetstat
	//Return List of ConnectionStat that match pid
	return []ConnectionStat{}, common.ErrNotImplementedError
}

//Parse netstat output into a collection of connections
func ParseNetstat() ([]ConnectionStat, error){
	var ret []ConnectionStat

	//Generate Netstat TCP Output
	tcp_out, err := exec.Command("cmd", "/c", "netstat -anop tcp").Output()
	if err == nil {
		//Iterate through netstat text and create ConnectionStat objects
		lines := strings.Split(string(tcp_out), "\n")

		for _, line := range lines {
			split := strings.Fields(line)
			if len(split) > 0 {
				if split[0] == "TCP" {
					//protocol := split[0]
					local_str := split[1]
					remote_str := split[2]
					state := split[3]
					pid,_ := strconv.Atoi(split[4])
					local_address, _ := ParseAddress(local_str)
					remote_address, _:= ParseAddress(remote_str)

					conn := ConnectionStat{
						Fd:     0,
						Family: 0,
						Type:   0,
						Laddr:  local_address,
						Raddr:  remote_address,
						Status: state,
						Pid:    int32(pid),
					}
					ret = append(ret, conn)
				}
			}
		}
	}

	//Generate Netstat UDP Output
	udp_out, err := exec.Command("cmd", "/c", "netstat -anop udp").Output()
	if err == nil {
		//Iterate through netstat text and create ConnectionStat objects
		lines := strings.Split(string(udp_out), "\n")

		for _, line := range lines {
			split := strings.Fields(line)
			if len(split) > 0 {
				if split[0] == "UDP" {
					local_str := split[1]
					pid,_ := strconv.Atoi(split[3])
					local_address, _ := ParseAddress(local_str)

					//FIXME: UDP doesn't have remote addresses
					//FIXME: UDP doesn't have status
					remote_address, _:= ParseAddress("0.0.0.0:0")


					conn := ConnectionStat{
						Fd:     0,
						Family: 0,
						Type:   0,
						Laddr:  local_address,
						Raddr:  remote_address,
						Status: "TIME_WAIT",
						Pid:    int32(pid),
					}
					ret = append(ret, conn)
				}
			}
		}
	}
	//Return list of ConnectionStat objects
	return ret, nil
}

//Parse addresses from netstat segment
func ParseAddress(addr_str string) (Addr, error){
	split_addr := strings.Split(addr_str, ":")
	ip := split_addr[0]
	port,_ := strconv.Atoi(split_addr[1])
	return Addr{
		IP:   ip,
		Port: uint32(port),
	}, nil
}

// Return a list of network connections opened returning at most `max`
// connections for each running process.
func ConnectionsMax(kind string, max int) ([]ConnectionStat, error) {
	return []ConnectionStat{}, common.ErrNotImplementedError
}

func FilterCounters() ([]FilterStat, error) {
	return nil, errors.New("NetFilterCounters not implemented for windows")
}

// NetProtoCounters returns network statistics for the entire system
// If protocols is empty then all protocols are returned, otherwise
// just the protocols in the list are returned.
// Not Implemented for Windows
func ProtoCounters(protocols []string) ([]ProtoCountersStat, error) {
	return nil, errors.New("NetProtoCounters not implemented for windows")
}
