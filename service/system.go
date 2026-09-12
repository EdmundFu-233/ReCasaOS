package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	net2 "net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/IceWhaleTech/CasaOS-Common/utils/command"
	exec2 "github.com/IceWhaleTech/CasaOS-Common/utils/exec"

	"github.com/IceWhaleTech/CasaOS-Common/utils/logger"
	"github.com/IceWhaleTech/CasaOS/common"
	"github.com/IceWhaleTech/CasaOS/model"
	"github.com/IceWhaleTech/CasaOS/pkg/config"
	"github.com/IceWhaleTech/CasaOS/pkg/filesecurity"
	"github.com/IceWhaleTech/CasaOS/pkg/utils/common_err"
	"github.com/IceWhaleTech/CasaOS/pkg/utils/file"
	"github.com/IceWhaleTech/CasaOS/pkg/utils/httper"
	"github.com/IceWhaleTech/CasaOS/pkg/utils/ip_helper"
	"github.com/tidwall/gjson"
	"go.uber.org/zap"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
)

type SystemService interface {
	UpdateSystemVersion(version string) error
	GetSystemConfigDebug() []string
	GetCasaOSLogs(lineNumber int) string
	UpdateAssist()
	UpSystemPort(port string)
	GetTimeZone() string
	UpAppOrderFile(str, id string)
	GetAppOrderFile(id string) []byte
	GetNet(physics bool) []string
	GetNetInfo() []net.IOCountersStat
	GetCpuCoreNum() int
	GetCpuPercent() float64
	GetMemInfo() map[string]interface{}
	GetCpuInfo() []cpu.InfoStat
	GetDirPath(path string) ([]model.Path, error)
	GetDirPathPage(ctx context.Context, path string, index, size int) ([]model.Path, int64, error)
	GetDirPathOne(path string) (m model.Path)
	GetNetState(name string) string
	GetDiskInfo() *disk.UsageStat
	GetSysInfo() host.InfoStat
	GetDeviceTree() string
	GetDeviceInfo() model.DeviceInfo
	CreateFile(path string) (int, error)
	RenameFile(oldF, newF string) (int, error)
	MkdirAll(path string) (int, error)
	GetCPUTemperature() int
	GetCPUPower() map[string]string
	GetMacAddress() (string, error)
	SystemReboot() error
	SystemShutdown() error
	GetSystemEntry() string
	GenreateSystemEntry()
}
type systemService struct{}

const (
	// ManagedDirectoryPageLimit bounds entries retained for one explicitly
	// paginated response. The scanner still walks the directory to produce an
	// exact total of valid visible entries.
	ManagedDirectoryPageLimit = 512
	// ManagedDirectoryLegacyPageSize preserves the response metadata expected by
	// path-only CasaOS-UI callers. That mode is internally retained at the lower
	// raw scan limit and fails atomically rather than truncating above the limit.
	ManagedDirectoryLegacyPageSize = 100_000
	// ManagedDirectoryRawScanLimit is the maximum number of raw directory entries
	// accepted for one listing. A single additional entry may be read only as a
	// sentinel to distinguish an exactly-full directory from an over-budget one.
	ManagedDirectoryRawScanLimit  = 10_000
	managedDirectoryReadBatchSize = 256
	managedDirectoryListingLimit  = 4
	legacyDirectoryFilterInternal = false
	pagedDirectoryFilterInternal  = true
)

var (
	ErrInvalidManagedDirectoryPage = errors.New("invalid managed directory page")
	ErrManagedDirectoryScanLimit   = errors.New("managed directory listing exceeds raw scan limit")
	ErrManagedDirectoryListingBusy = errors.New("managed directory listing capacity is busy")
	managedDirectoryListings       = newManagedDirectoryListingGate(managedDirectoryListingLimit)
)

type managedDirectoryListingGate struct {
	slots chan struct{}
}

func newManagedDirectoryListingGate(capacity int) *managedDirectoryListingGate {
	return &managedDirectoryListingGate{slots: make(chan struct{}, capacity)}
}

func (g *managedDirectoryListingGate) acquire(ctx context.Context) (func(), error) {
	if ctx == nil {
		return nil, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case g.slots <- struct{}{}:
		var once sync.Once
		release := func() {
			once.Do(func() { <-g.slots })
		}
		if err := ctx.Err(); err != nil {
			release()
			return nil, err
		}
		return release, nil
	default:
		return nil, ErrManagedDirectoryListingBusy
	}
}

// AcquireManagedDirectoryListing reserves one bounded end-to-end listing slot.
// HTTP callers hold the returned lease through response serialization; the
// release function is idempotent. Admission and context checks bound aggregate
// work but cannot interrupt a filesystem syscall already blocked in the kernel.
func AcquireManagedDirectoryListing(ctx context.Context) (func(), error) {
	return managedDirectoryListings.acquire(ctx)
}

func (c *systemService) GetDeviceInfo() model.DeviceInfo {
	m := model.DeviceInfo{}
	m.OS_Version = common.VERSION
	err, portStr := MyService.Gateway().GetPort()
	if err != nil {
		m.Port = 80
	} else {
		port := gjson.Get(portStr, "data")
		if len(port.Raw) == 0 {
			m.Port = 80
		} else {
			p, err := strconv.Atoi(port.Raw)
			if err != nil {
				m.Port = 80
			} else {
				m.Port = p
			}
		}
	}
	allIpv4 := ip_helper.GetDeviceAllIPv4()
	ip := []string{}
	nets := MyService.System().GetNet(true)
	for _, n := range nets {
		if v, ok := allIpv4[n]; ok {
			{
				ip = append(ip, v)
			}
		}
	}

	m.LanIpv4 = ip
	h, err := host.Info() /*  */
	if err == nil {
		m.DeviceName = h.Hostname
	}
	mb := model.BaseInfo{}

	err = json.Unmarshal(file.ReadFullFile(config.AppInfo.DBPath+"/baseinfo.conf"), &mb)
	if err == nil {
		m.Hash = mb.Hash
	}

	osRelease, _ := file.ReadOSRelease()
	m.DeviceModel = osRelease["MODEL"]
	m.DeviceSN = osRelease["SN"]
	res := httper.Get("http://127.0.0.1:"+strconv.Itoa(m.Port)+"/v1/users/status", nil)
	init := gjson.Get(res, "data.initialized")
	m.Initialized, _ = strconv.ParseBool(init.Raw)

	return m
}

func (c *systemService) GenreateSystemEntry() {
	modelsPath := "/var/lib/casaos/www/modules"
	entryFileName := "entry.json"
	entryFilePath := filepath.Join(config.AppInfo.DBPath, "db", entryFileName)
	if err := file.IsNotExistCreateFile(entryFilePath); err != nil && !errors.Is(err, os.ErrExist) {
		logger.Error("create entry file error", zap.Error(err))
		return
	}

	dir, err := os.ReadDir(modelsPath)
	if err != nil {
		logger.Error("read dir error", zap.Error(err))
		return
	}
	json := "["
	for _, v := range dir {
		data, err := os.ReadFile(filepath.Join(modelsPath, v.Name(), entryFileName))
		if err != nil {
			logger.Error("read entry file error", zap.Error(err))
			continue
		}
		json += string(data) + ","
	}
	json = strings.TrimRight(json, ",")
	json += "]"
	err = os.WriteFile(entryFilePath, []byte(json), 0o600)
	if err != nil {
		logger.Error("write entry file error", zap.Error(err))
		return
	}
}

func (c *systemService) GetSystemEntry() string {
	modelsPath := "/var/lib/casaos/www/modules"
	entryFileName := "entry.json"
	dir, err := os.ReadDir(modelsPath)
	if err != nil {
		logger.Error("read dir error", zap.Error(err))
		return ""
	}
	json := "["
	for _, v := range dir {
		data, err := os.ReadFile(filepath.Join(modelsPath, v.Name(), entryFileName))
		if err != nil {
			logger.Error("read entry file error", zap.Error(err))
			continue
		}
		json += string(data) + ","
	}
	json = strings.TrimRight(json, ",")
	json += "]"
	if err != nil {
		logger.Error("write entry file error", zap.Error(err))
		return ""
	}
	return json
}

func (c *systemService) GetMacAddress() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	nets := MyService.System().GetNet(true)
	for _, v := range interfaces {
		for _, n := range nets {
			if v.Name == n {
				return v.HardwareAddr, nil
			}
		}
	}
	return "", errors.New("not found")
}

func (c *systemService) MkdirAll(path string) (int, error) {
	roots, err := filesecurity.ManagementFileRoots()
	if err != nil {
		return common_err.SERVICE_ERROR, err
	}
	_, err = roots.Stat(path)
	if err == nil {
		return common_err.DIR_ALREADY_EXISTS, nil
	} else {
		if os.IsNotExist(err) {
			if err := roots.MkdirAll(path, 0o750); err != nil {
				return common_err.SERVICE_ERROR, err
			}
			return common_err.SUCCESS, nil
		} else if strings.Contains(err.Error(), ": not a directory") {
			return common_err.FILE_OR_DIR_EXISTS, err
		}
	}
	return common_err.SERVICE_ERROR, err
}

func (c *systemService) RenameFile(oldF, newF string) (int, error) {
	roots, err := filesecurity.ManagementFileRoots()
	if err != nil {
		return common_err.SERVICE_ERROR, err
	}
	_, err = roots.Stat(newF)
	if err == nil {
		return common_err.DIR_ALREADY_EXISTS, nil
	} else {
		if os.IsNotExist(err) {
			err := roots.RenameNoReplace(oldF, newF)
			if err != nil {
				return common_err.SERVICE_ERROR, err
			}
			return common_err.SUCCESS, nil
		}
	}
	return common_err.SERVICE_ERROR, err
}

func (c *systemService) CreateFile(path string) (int, error) {
	roots, err := filesecurity.ManagementFileRoots()
	if err != nil {
		return common_err.SERVICE_ERROR, err
	}
	_, err = roots.Stat(path)
	if err == nil {
		return common_err.FILE_OR_DIR_EXISTS, nil
	} else {
		if os.IsNotExist(err) {
			created, createErr := roots.CreateExclusive(path, 0o600)
			if createErr != nil {
				return common_err.SERVICE_ERROR, createErr
			}
			defer created.Abort()
			if err := created.Close(); err != nil {
				return common_err.SERVICE_ERROR, err
			}
			return common_err.SUCCESS, nil
		}
	}
	return common_err.SERVICE_ERROR, err
}

func (c *systemService) GetDeviceTree() string {
	if output, err := command.OnlyExec("source " + config.AppInfo.ShellPath + "/helper.sh ;GetDeviceTree"); err != nil {
		return ""
	} else {
		return output
	}
}

func (c *systemService) GetSysInfo() host.InfoStat {
	info, _ := host.Info()
	return *info
}

func (c *systemService) GetDiskInfo() *disk.UsageStat {
	path := "/"
	if runtime.GOOS == "windows" {
		path = "C:"
	}
	diskInfo, _ := disk.Usage(path)
	diskInfo.UsedPercent, _ = strconv.ParseFloat(fmt.Sprintf("%.1f", diskInfo.UsedPercent), 64)
	diskInfo.InodesUsedPercent, _ = strconv.ParseFloat(fmt.Sprintf("%.1f", diskInfo.InodesUsedPercent), 64)
	return diskInfo
}

func (c *systemService) GetNetState(name string) string {
	if output, err := command.OnlyExec("source " + config.AppInfo.ShellPath + "/helper.sh ;CatNetCardState " + name); err != nil {
		return ""
	} else {
		return output
	}
}

func (c *systemService) GetDirPathOne(path string) (m model.Path) {
	roots, err := filesecurity.ManagementFileRoots()
	if err != nil {
		return
	}
	f, err := roots.Stat(path)
	if err != nil {
		return
	}
	m.IsDir = f.IsDir()
	m.Name = f.Name()
	m.Path = path
	m.Size = f.Size()
	m.Date = f.ModTime()
	return
}

func (c *systemService) GetDirPath(path string) ([]model.Path, error) {
	release, err := AcquireManagedDirectoryListing(context.Background())
	if err != nil {
		return nil, err
	}
	defer release()
	dirs, _, err := c.getDirPathPage(context.Background(), path, 0, ManagedDirectoryRawScanLimit, false, legacyDirectoryFilterInternal)
	return dirs, err
}

type managedDirectoryPagePlan struct {
	offset       int64
	retainedSize int
	legacy       bool
}

func planManagedDirectoryPage(index, size int) (managedDirectoryPagePlan, error) {
	retainedSize := size
	legacyListing := index == 1 && size == ManagedDirectoryLegacyPageSize
	if legacyListing {
		retainedSize = ManagedDirectoryRawScanLimit
	}
	if index < 1 || retainedSize < 1 || (!legacyListing && size > ManagedDirectoryPageLimit) || index-1 > (int(^uint(0)>>1))/retainedSize {
		return managedDirectoryPagePlan{}, ErrInvalidManagedDirectoryPage
	}
	return managedDirectoryPagePlan{
		offset:       int64((index - 1) * retainedSize),
		retainedSize: retainedSize,
		legacy:       legacyListing,
	}, nil
}

// GetDirPathPage expects network callers to hold an admission lease across the
// complete response lifecycle. It does not acquire internally, avoiding a
// double slot while the route serializes a potentially large legacy response.
func (c *systemService) GetDirPathPage(ctx context.Context, path string, index, size int) ([]model.Path, int64, error) {
	plan, err := planManagedDirectoryPage(index, size)
	if err != nil {
		return nil, 0, err
	}
	return c.getDirPathPage(ctx, path, plan.offset, plan.retainedSize, true, pagedDirectoryFilterInternal)
}

func (c *systemService) getDirPathPage(ctx context.Context, path string, offset int64, size int, hideActiveTargets, filterInternalEntries bool) ([]model.Path, int64, error) {
	if ctx == nil {
		return nil, 0, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	if path == "" {
		entry := model.Path{Name: "DATA", Path: "/DATA/", IsDir: true, Date: time.Now()}
		if offset == 0 && size > 0 {
			return []model.Path{entry}, 1, nil
		}
		return []model.Path{}, 1, nil
	}
	hiddenTargets := map[string]string(nil)
	if hideActiveTargets {
		// One immutable queue snapshot defines visibility for the entire scan, so
		// a concurrent operation transition cannot make total and content disagree.
		hiddenTargets = ActiveFileOperationTargets()
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	if path == "/DATA" {
		sysType := runtime.GOOS
		if sysType == "windows" {
			path = "C:\\CasaOS\\DATA"
		}
		if sysType == "darwin" {
			path = "./CasaOS/DATA"
		}

	}

	roots, err := filesecurity.ManagementFileRoots()
	if err != nil {
		return nil, 0, err
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	location, err := roots.Match(path)
	if err != nil {
		return nil, 0, err
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	directory, err := roots.OpenDirectory(location.Canonical)
	if err != nil {
		return nil, 0, err
	}
	return readManagedDirectoryPage(ctx, directory, location.Canonical, offset, size, hiddenTargets, filterInternalEntries, func(name string) (fs.FileInfo, error) {
		return roots.StatDirectoryEntry(directory, name)
	})
}

// readManagedDirectoryPage scans using positive bounded reads, retains only the
// requested valid-entry window, and still counts every valid entry exactly.
// Symlinks and non-regular special files are always filtered. Paged callers also
// filter the internal .temp directory and one snapshot of active operation
// targets before total and pagination; the legacy wrapper keeps its base .temp
// behavior for non-HTTP compatibility.
func readManagedDirectoryPage(ctx context.Context, directory fs.ReadDirFile, directoryPath string, offset int64, size int, hiddenTargets map[string]string, filterInternalEntries bool, statEntry func(string) (fs.FileInfo, error)) (page []model.Path, total int64, resultErr error) {
	if ctx == nil || directory == nil || offset < 0 || size < 1 || statEntry == nil {
		return nil, 0, ErrInvalidManagedDirectoryPage
	}
	defer func() {
		closeErr := directory.Close()
		if resultErr != nil || closeErr != nil {
			page = nil
			total = 0
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()

	page = make([]model.Path, 0, size)
	rawScanned := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
		readSize := managedDirectoryReadBatchSize
		remaining := ManagedDirectoryRawScanLimit - rawScanned
		if remaining < readSize {
			// Allow one sentinel entry to prove that the accepted raw-entry
			// limit was exceeded without inspecting or returning that entry.
			readSize = remaining + 1
		}
		entries, readErr := directory.ReadDir(readSize)
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
		if len(entries) > remaining {
			return nil, 0, ErrManagedDirectoryScanLimit
		}
		if len(entries) == 0 && readErr == nil {
			return nil, 0, io.ErrNoProgress
		}

		for _, entry := range entries {
			rawScanned++
			if err := ctx.Err(); err != nil {
				return nil, 0, err
			}
			info, infoErr := statEntry(entry.Name())
			if infoErr != nil {
				if errors.Is(infoErr, fs.ErrNotExist) {
					// A concurrently removed entry is absent from this snapshot.
					continue
				}
				return nil, 0, fmt.Errorf("stat managed directory entry: %w", infoErr)
			}
			if !info.IsDir() && !info.Mode().IsRegular() {
				continue
			}
			filePath := filepath.Join(directoryPath, entry.Name())
			if filterInternalEntries && entry.Name() == ".temp" && info.IsDir() {
				continue
			}
			if _, hidden := hiddenTargets[filePath]; hidden {
				continue
			}

			position := total
			total++
			if position < offset || int64(len(page)) >= int64(size) {
				continue
			}
			page = append(page, model.Path{
				Name:  entry.Name(),
				Path:  filePath,
				IsDir: info.IsDir(),
				Date:  info.ModTime(),
				Size:  info.Size(),
			})
		}

		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return page, total, nil
			}
			return nil, 0, fmt.Errorf("read managed directory: %w", readErr)
		}
	}
}

func (c *systemService) GetCpuInfo() []cpu.InfoStat {
	info, _ := cpu.Info()
	return info
}

func (c *systemService) GetMemInfo() map[string]interface{} {
	memInfo, _ := mem.VirtualMemory()
	memInfo.UsedPercent, _ = strconv.ParseFloat(fmt.Sprintf("%.1f", memInfo.UsedPercent), 64)
	memData := make(map[string]interface{})
	memData["total"] = memInfo.Total
	memData["available"] = memInfo.Available
	memData["used"] = memInfo.Used
	memData["free"] = memInfo.Free
	memData["usedPercent"] = memInfo.UsedPercent
	return memData
}

func (c *systemService) GetCpuPercent() float64 {
	percent, _ := cpu.Percent(0, false)
	value, _ := strconv.ParseFloat(fmt.Sprintf("%.1f", percent[0]), 64)
	return value
}

func (c *systemService) GetCpuCoreNum() int {
	count, _ := cpu.Counts(false)
	return count
}

func (c *systemService) GetNetInfo() []net.IOCountersStat {
	parts, _ := net.IOCounters(true)
	return parts
}

func (c *systemService) GetNet(physics bool) []string {
	t := "1"
	if physics {
		t = "2"
	}

	if output, err := command.OnlyExec("source " + config.AppInfo.ShellPath + "/helper.sh ;GetNetCard " + t); err != nil {
		return []string{}
	} else {
		return strings.Split(output, "\n")
	}
}

func (s *systemService) UpdateSystemVersion(_ string) error {
	keyName := "casa_version"
	Cache.Delete(keyName)
	return errors.New("automatic updates are disabled until ReCasaOS publishes a signed component manifest and rollback-capable installer")
}

func (s *systemService) UpdateAssist() {
	command.ExecResultStrArray("source " + config.AppInfo.ShellPath + "/assist.sh")
}

func (s *systemService) GetTimeZone() string {
	if output, err := command.OnlyExec("source " + config.AppInfo.ShellPath + "/helper.sh ;GetTimeZone"); err != nil {
		return ""
	} else {
		return output
	}
}

func (s *systemService) GetSystemConfigDebug() []string {
	if output, err := command.OnlyExec("source " + config.AppInfo.ShellPath + "/helper.sh ;GetSysInfo"); err != nil {
		return []string{}
	} else {
		return strings.Split(output, "\n")
	}
}

func (s *systemService) UpAppOrderFile(str, id string) {
	file.WriteToPath([]byte(str), config.AppInfo.DBPath+"/"+id, "app_order.json")
}

func (s *systemService) GetAppOrderFile(id string) []byte {
	return file.ReadFullFile(config.AppInfo.UserDataPath + "/" + id + "/app_order.json")
}

func (s *systemService) UpSystemPort(port string) {
	if len(port) > 0 && port != config.ServerInfo.HttpPort {
		config.Cfg.Section("server").Key("HttpPort").SetValue(port)
		config.ServerInfo.HttpPort = port
	}
	config.Cfg.SaveTo(config.SystemConfigInfo.ConfigPath)
}

func (s *systemService) GetCasaOSLogs(lineNumber int) string {
	file, err := os.Open(filepath.Join(config.AppInfo.LogPath, fmt.Sprintf("%s.%s",
		config.AppInfo.LogSaveName,
		config.AppInfo.LogFileExt,
	)))
	if err != nil {
		return err.Error()
	}
	defer file.Close()
	content, err := io.ReadAll(file)
	if err != nil {
		return err.Error()
	}

	return string(content)
}

func GetDeviceAllIP() []string {
	var address []string
	addrs, err := net2.InterfaceAddrs()
	if err != nil {
		return address
	}
	for _, a := range addrs {
		if ipNet, ok := a.(*net2.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To16() != nil {
				address = append(address, ipNet.IP.String())
			}
		}
	}
	return address
}

// find thermal_zone of cpu.
// assertions:
//   - thermal_zone "type" and "temp" are required fields
//     (https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-class-thermal)
func GetCPUThermalZone() string {
	keyName := "cpu_thermal_zone"

	var path string
	if result, ok := Cache.Get(keyName); ok {
		path, ok = result.(string)
		if ok {
			return path
		}
	}

	var name string
	cpu_types := []string{"x86_pkg_temp", "cpu", "CPU", "soc"}
	stub := "/sys/devices/virtual/thermal/thermal_zone"
	for i := 0; i < 100; i++ {
		path = stub + strconv.Itoa(i)
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			name = strings.TrimSuffix(string(file.ReadFullFile(path+"/type")), "\n")
			for _, s := range cpu_types {
				if strings.HasPrefix(name, s) {
					//logger.Info(fmt.Sprintf("CPU thermal zone found: %s, path: %s.", name, path))
					Cache.SetDefault(keyName, path)
					return path
				}
			}
		} else {
			if len(name) > 0 { // proves at least one zone
				path = stub + "0"
			} else {
				path = ""
			}
			break
		}
	}

	Cache.SetDefault(keyName, path)
	return path
}

func (s *systemService) GetCPUTemperature() int {
	outPut := ""
	path := GetCPUThermalZone()
	if len(path) > 0 {
		outPut = string(file.ReadFullFile(path + "/temp"))
	} else {
		outPut = string(file.ReadFullFile("/sys/class/hwmon/hwmon0/temp1_input"))
		if len(outPut) == 0 {
			outPut = "0"
		}
	}

	celsius, _ := strconv.Atoi(strings.TrimSpace(outPut))

	if celsius > 1000 {
		celsius = celsius / 1000
	}
	return celsius
}

func (s *systemService) GetCPUPower() map[string]string {
	data := make(map[string]string, 2)
	data["timestamp"] = strconv.FormatInt(time.Now().Unix(), 10)
	if file.Exists("/sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj") {
		data["value"] = strings.TrimSpace(string(file.ReadFullFile("/sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj")))
	} else {
		data["value"] = "0"
	}
	return data
}

func (s *systemService) SystemReboot() error {
	arg := []string{"6"}
	cmd := exec2.Command("init", arg...)
	_, err := cmd.CombinedOutput()
	if err != nil {
		return err
	}
	return nil
}

func (s *systemService) SystemShutdown() error {
	arg := []string{"0"}
	cmd := exec2.Command("init", arg...)
	_, err := cmd.CombinedOutput()
	if err != nil {
		return err
	}
	return nil
}

func NewSystemService() SystemService {
	return &systemService{}
}
