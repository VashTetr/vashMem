package MemoryScanning

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	user32DLL              = syscall.NewLazyDLL("user32.dll")
	enumWindowsProc        = user32DLL.NewProc("EnumWindows")
	getWindowThreadProcess = user32DLL.NewProc("GetWindowThreadProcessId")
	isWindowVisibleProc    = user32DLL.NewProc("IsWindowVisible")
	openProcessProc        = kernel32.NewProc("OpenProcess")
	getWindowLong          = user32DLL.NewProc("GetWindowLongA")
	getWindowLongPtr       = user32DLL.NewProc("GetWindowLongPtrA")
	readProcessMemory      = kernel32.NewProc("ReadProcessMemory")
	writeProcessMemory     = kernel32.NewProc("WriteProcessMemory")
	err                    error
	pid                    uint32
	aobCache               []AobCache
	convertedAob           []string
	addrLocation           int64
	memRead                uint64
	relativeLocation       uintptr
)

const (
	PROCESS_ALL_ACCESS                = 0x1F0FFF
	PROCESS_QUERY_INFORMATION         = 0x0400
	PROCESS_VM_READ                   = 0x0010
	LIST_MODULES_ALL                  = 0x03
	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
	PROCESS_VM_WRITE                  = 0x0020
	PROCESS_VM_OPERATION              = 0x0008
	PROCESS_QUERY_INFO                = 0x0400
	GWL_HINSTANCE                     = int32(-6)
	TH32CS_SNAPMODULE                 = 0x00000008
	TH32CS_SNAPMODULE32               = 0x00000010
)

type ModuleEntry32 struct {
	dwSize        uint32
	th32ModuleID  uint32
	th32ProcessID uint32
	GlblcntUsage  uint32
	ProccntUsage  uint32
	modBaseAddr   uintptr
	modBaseSize   uint32
	hModule       syscall.Handle
	szModule      [256]uint16
	szExePath     [260]uint16
}
type AobCache struct {
	aobPattern string
	address    uintptr
	expected   string
}

type ModuleInfo struct {
	Name        string
	FileName    string
	lpBaseOfDll uintptr
	SizeOfImage int
	EntryPoint  uintptr
}

type MemoryInfo struct {
	BaseAddress uintptr
	RegionSize  uintptr
	State       uint32
	Protect     uint32
}

func GetPointerDynamic(pHandle *uintptr, aobScan *string, offset int64, pid *uint32, size int) uintptr {
	if size == 0 {
		size = 4
	}

	if convertedAob, err = HexStringToPattern(*aobScan); err != nil {
		fmt.Println("could not convert aobScan to converted AOB", aobScan, convertedAob)
	}

	addrLocation = ProcessPatternScan(pHandle, 0, 0, convertedAob...) + offset

	if memRead, err = ReadMemory(uintptr(addrLocation), int(*pid), size); err != nil {
		fmt.Println("address location of pattern scan invalid", err)
	}
	relativeLocation = uintptr(memRead)

	return relativeLocation

}
func GetModulePatternStatic(hProcess *uintptr, moduleName string, aobScan *string, size int) (uintptr, error) {
	if size == 0 {
		size = 4
	}
	prebuf := make([]byte, 32)
	buf := make([]byte, 32)
	for i := 0; i < len(aobCache); i++ {
		if aobCache[i].aobPattern == *aobScan {
			ReadRaw(hProcess, &aobCache[i].address, prebuf)
			if aobCache[i].expected == ByteArrayToString(prebuf) {
				fmt.Println(aobCache[i].address, prebuf, buf)
				return uintptr(aobCache[i].address), nil
			}
		}
	}

	if convertedAob, err = HexStringToPattern(*aobScan); err != nil {
		fmt.Printf("could not convert aobScan (%v) to converted AOB(%v)\n", *aobScan, convertedAob)
	}

	if addrLocation, err = ModulePatternScan(hProcess, moduleName, convertedAob...); err != nil {
		fmt.Println("address location of module pattern scan invalid", err)
	}
	relativeLocation = uintptr(addrLocation)
	ReadRaw(hProcess, &relativeLocation, buf)
	aobCache = append(aobCache,
		AobCache{
			*aobScan,
			uintptr(relativeLocation),
			ByteArrayToString(buf),
		},
	)
	return relativeLocation, nil
}

func GetPointerStatic(pHandle, base *uintptr, aobScan *string, offset int64, pid *uint32, size int) uintptr {
	if size == 0 {
		size = 4
	}
	prebuf := make([]byte, 32)
	buf := make([]byte, 32)
	for i := 0; i < len(aobCache); i++ {
		if aobCache[i].aobPattern == *aobScan {
			ReadRaw(pHandle, &aobCache[i].address, prebuf)
			if aobCache[i].expected == ByteArrayToString(prebuf) {
				return uintptr(aobCache[i].address)
			}
		}
	}
	if convertedAob, err = HexStringToPattern(*aobScan); err != nil {
		fmt.Println("could not convert aobScan to converted AOB", aobScan, convertedAob)
	}
	addrLocation = ProcessPatternScan(pHandle, 0, 0, convertedAob...) + offset

	if memRead, err = ReadMemory(uintptr(addrLocation), int(*pid), size); err != nil {
		fmt.Println("address location of pattern scan invalid", err)
	}
	relativeLocation = uintptr(memRead) - *base

	ReadRaw(pHandle, &relativeLocation, buf)
	aobCache = append(aobCache,
		AobCache{
			*aobScan,
			uintptr(relativeLocation),
			ByteArrayToString(buf),
		},
	)
	return relativeLocation

}
func Int64ToHex(num int64) string {
	hexString := strconv.FormatInt(num, 16)
	return hexString
}
func UintptrToHex(ptr uintptr) string {
	hexString := strconv.FormatUint(uint64(ptr), 16)
	return hexString
}
func ByteArrayToString(arr []byte) string {
	str := ""
	for _, val := range arr {
		str += strconv.Itoa(int(val)) + " "
	}
	return strings.TrimSpace(str)
}

func GetInstanceHandle(handle uintptr) (uintptr, error) {
	var proc *syscall.LazyProc
	var index int32

	if unsafe.Sizeof(uintptr(0)) == 4 {
		proc = getWindowLong
		index = GWL_HINSTANCE
	} else {
		proc = getWindowLongPtr
		index = GWL_HINSTANCE
	}

	r1, _, err := proc.Call(handle, uintptr(index))
	if err != syscall.Errno(0) {
		return 0, fmt.Errorf("failed to get instance handle: %v", err)
	}

	return r1, nil
}

func GetPid(exeName string) uint32 {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(snapshot)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))

	for err := windows.Process32First(snapshot, &pe); err == nil; err = windows.Process32Next(snapshot, &pe) {
		if strings.ToLower(windows.UTF16ToString(pe.ExeFile[:])) == strings.ToLower(exeName) {
			return pe.ProcessID
		}
	}
	return 0
}

func GetHwndByProcessID(pid uint32) (uintptr, error) {
	var hwnd uintptr
	found := false

	callback := syscall.NewCallback(func(window uintptr, lParam uintptr) uintptr {
		var processID uint32
		getWindowThreadProcess.Call(window, uintptr(unsafe.Pointer(&processID)))

		if processID == pid {
			isVisible, _, _ := isWindowVisibleProc.Call(window)
			if isVisible != 0 {
				hwnd = window
				found = true
				return 0
			}
		}
		return 1
	})

	ret, _, callErr := enumWindowsProc.Call(callback, 0)

	if ret == 0 && !found {
		return 0, fmt.Errorf("failed to enumerate windows: %v", callErr)
	}

	if hwnd == 0 {
		return 0, fmt.Errorf("no window found for process ID %d", pid)
	}

	return hwnd, nil
}

func IntToHex(num int) string {
	hexStr := fmt.Sprintf("0x%x", num)
	return hexStr
}

func ReadMemory(MADDRESS uintptr, pid int, size int) (uint64, error) {
	if size == 0 {
		size = 4
	}

	buffer := make([]byte, size)

	handle, _, err := openProcessProc.Call(uintptr(PROCESS_VM_READ), 0, uintptr(pid))
	if handle == 0 {
		return 0, fmt.Errorf("failed to open process: %v", err)
	}
	defer syscall.CloseHandle(syscall.Handle(handle))

	var totalBytesRead uintptr
	for totalBytesRead < uintptr(size) {
		var bytesRead uintptr
		r1, _, err := readProcessMemory.Call(handle, MADDRESS+totalBytesRead, uintptr(unsafe.Pointer(&buffer[totalBytesRead])), uintptr(size-int(totalBytesRead)), uintptr(unsafe.Pointer(&bytesRead)))
		if r1 == 0 {
			return 0, fmt.Errorf("failed to read memory: %v", err)
		}
		totalBytesRead += bytesRead
		if bytesRead == 0 {
			return 0, fmt.Errorf("only part of the memory was read: expected %d bytes, but read %d bytes", size, totalBytesRead)
		}
	}

	var result uint64
	for i := 0; i < size; i++ {
		result |= uint64(buffer[i]) << (8 * i)
	}

	return result, nil
}
func ReadMemoryStr(address uintptr, pid int) (string, error) {
	handle, _, err := openProcessProc.Call(uintptr(PROCESS_VM_READ), 0, uintptr(pid))
	if handle == 0 {
		return "", fmt.Errorf("failed to open process: %v", err)
	}
	defer syscall.CloseHandle(syscall.Handle(handle))

	var testStr strings.Builder
	var output byte
	for {
		var bytesRead uintptr
		_, _, err = readProcessMemory.Call(
			handle,
			address,
			uintptr(unsafe.Pointer(&output)),
			1,
			uintptr(unsafe.Pointer(&bytesRead)),
		)
		if bytesRead == 0 || output == 0 {
			return testStr.String(), nil
		}
		testStr.WriteByte(output)
		address++
	}
}

func WriteProcessMemory(pid int, address uintptr, valueToWrite uint64, size int) error {
	var value [8]byte
	for i := 0; i < size; i++ {
		value[i] = byte(valueToWrite >> (8 * i))
	}

	handle, _, err := openProcessProc.Call(uintptr(PROCESS_VM_WRITE|PROCESS_VM_OPERATION), 0, uintptr(pid))
	if handle == 0 {
		return fmt.Errorf("failed to open process: %v", err)
	}
	defer syscall.CloseHandle(syscall.Handle(handle))

	_, _, err = writeProcessMemory.Call(handle, address, uintptr(unsafe.Pointer(&value[0])), uintptr(size), 0)
	if err != syscall.Errno(0) {
		return fmt.Errorf("failed to write memory: %v", err)
	}

	return nil
}

func GetAddress(PID int, Base uintptr, Address uintptr, Offset string) (uintptr, error) {
	PointerBase := Base + Address

	if Offset == "" {
		return PointerBase, nil
	}
	y, err := ReadMemory(PointerBase, PID, 4)
	if err != nil {
		return 0, err
	}

	offsetSplit := strings.Split(Offset, "+")
	offsetCount := len(offsetSplit)

	for i := 0; i < offsetCount; i++ {
		offsetValue := offsetSplit[i]
		offset, err := strconv.ParseUint(offsetValue, 0, 64)
		if err != nil {
			return 0, fmt.Errorf("failed to parse offset: %v", err)
		}
		if i == offsetCount-1 {
			finalAddress := uintptr(y + offset)
			return finalAddress, nil
		} else {
			newAddress := y + offset
			y, err = ReadMemory(uintptr(newAddress), PID, 4)
			if err != nil {
				return 0, err
			}
		}
	}

	return 0, nil
}

func HexToFloat(d uint32) float32 {
	sign := (d >> 31) & 1
	exponent := (d >> 23) & 0xFF
	mantissa := d & 0x7FFFFF

	return float32((float64(1 - 2*int(sign))) * math.Pow(2, float64(exponent-127)) * (1 + float64(mantissa)/8388608))
}

func HexToFloatBig(x uint32) float32 {
	sign := (x >> 31) & 1
	exponent := (x >> 23) & 0xFF
	mantissa := x & 0x7FFFFF

	return float32((float64(1 - 2*int(sign))) * math.Pow(2, float64(exponent-150)) * (float64(0x800000 | mantissa)))
}

func IntToHexOld(value int) string {
	var hexStr string

	for i := 7; i >= 0; i-- {
		n := (value >> (i * 4)) & 0xf

		if n > 9 {
			hexStr += string('A' + n - 10)
		} else {
			hexStr += fmt.Sprintf("%X", n)
		}
	}

	return "0x" + hexStr
}
func ProcessPatternScan(hProcess *uintptr, startAddress uintptr, endAddress uintptr, aobPattern ...string) int64 {
	const (
		MEM_COMMIT    = 0x1000
		MEM_MAPPED    = 0x40000
		MEM_PRIVATE   = 0x20000
		PAGE_NOACCESS = 0x01
		PAGE_GUARD    = 0x100
	)

	address := startAddress

	if endAddress == 0 {
		if unsafe.Sizeof(uintptr(0)) == 8 {
			endAddress = 0x7FFFFFFFFFF
		} else {
			endAddress = 0xFFFFFFFF
		}
	}

	patternMask, aobBuffer, patternSize := GetNeedleFromAOBPattern(&aobPattern)
	if patternSize <= 0 {
		return -10
	}

	for address <= endAddress {
		var memInfo MemoryInfo

		if !VirtualQueryEx(*hProcess, address, &memInfo) {
			fmt.Printf("VirtualQueryEx failed for address: 0x%X\n", address)
			return -1
		}

		if address == startAddress {
			memInfo.RegionSize -= address - memInfo.BaseAddress
		}

		if memInfo.State == MEM_COMMIT &&
			(memInfo.Protect&(PAGE_NOACCESS|PAGE_GUARD) == 0) &&
			memInfo.RegionSize >= uintptr(patternSize) {

			result := PatternScan(hProcess, &address, &memInfo.RegionSize, patternMask, &aobBuffer)
			if result > 0 {
				return result
			} else {
				//fmt.Printf("Pattern not found in region: 0x%X - 0x%X\n", address, address+memInfo.RegionSize)
			}
		} else {
			//fmt.Printf("Skipping memory region: 0x%X - 0x%X (state: %X, protect: %X)\n", memInfo.BaseAddress, memInfo.BaseAddress+memInfo.RegionSize, memInfo.State, memInfo.Protect)
		}

		address += memInfo.RegionSize
	}

	return 0
}

func GetNeedleFromAOBPattern(aobPattern *[]string) (string, []byte, int) {
	var patternMask string
	var needleBuffer []byte

	for _, v := range *aobPattern {
		if v == "??" {
			patternMask += "?"
			needleBuffer = append(needleBuffer, 0)
		} else {
			patternMask += "x"
			bytes, err := HexStringToBytes(v)
			if err != nil {
				fmt.Println("error in needle aob", err)
				return "", nil, -1
			}
			needleBuffer = append(needleBuffer, bytes...)
		}
	}
	return patternMask, needleBuffer, len(needleBuffer)
}
func HexStringToBytes(hexString string) ([]byte, error) {
	if strings.HasPrefix(hexString, "0x") {
		hexString = hexString[2:]
	}

	bytes := make([]byte, len(hexString)/2)
	for i := 0; i < len(hexString); i += 2 {
		val, err := strconv.ParseInt(hexString[i:i+2], 16, 64)
		if err != nil {
			fmt.Println(hexString[i:i+2], hexString)
			return nil, fmt.Errorf("error parsing hex string '%s': %w", hexString[i:i+2], err)
		}
		bytes[i/2] = byte(val)
	}

	return bytes, nil
}

type MEMORY_BASIC_INFORMATION struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

var kernel32a = syscall.MustLoadDLL("kernel32.dll")
var VirtualQueryExProc = kernel32a.MustFindProc("VirtualQueryEx")

func VirtualQueryEx(hProcess uintptr, address uintptr, memInfo *MemoryInfo) bool {
	var mbi MEMORY_BASIC_INFORMATION

	_, _, err := VirtualQueryExProc.Call(
		hProcess,
		address,
		uintptr(unsafe.Pointer(&mbi)),
		unsafe.Sizeof(mbi),
	)

	if err != nil && err.(syscall.Errno) != 0 {
		return false
	}

	memInfo.BaseAddress = mbi.BaseAddress
	memInfo.RegionSize = mbi.RegionSize
	memInfo.State = mbi.State
	memInfo.Protect = mbi.Protect

	return true
}

func PatternScan(hProcess *uintptr, address *uintptr, sizeOfRegionBytes *uintptr, patternMask string, needleBuffer *[]byte) int64 {
	buffer := make([]byte, *sizeOfRegionBytes)
	if !ReadRaw(hProcess, address, buffer) {
		return -1
	}

	offset, found := BufferScanForMaskedPattern(&buffer, patternMask, needleBuffer)
	if found {
		return int64(*address + uintptr(offset))
	}
	return 0
}

func BufferScanForMaskedPattern(haystack *[]byte, patternMask string, needle *[]byte) (int, bool) {
	needleSize := len(*needle)

	for i := 0; i <= len(*haystack)-needleSize; i++ {
		match := true
		for j := 0; j < needleSize; j++ {
			if patternMask[j] == 'x' && (*haystack)[i+j] != (*needle)[j] {
				match = false
				break
			}
		}

		if match {
			return i, true
		}
	}

	return -1, false
}

var readProcessMemoryProc = kernel32a.MustFindProc("ReadProcessMemory")

func ReadRaw(hProcess *uintptr, address *uintptr, buffer []byte, offsets ...uintptr) bool {
	targetAddress := GetAddressFromOffsets(*address, offsets...)

	var numberOfBytesRead uint32

	res, _, err := readProcessMemoryProc.Call(
		*hProcess,
		targetAddress,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		uintptr(unsafe.Pointer(&numberOfBytesRead)),
	)

	if res == 0 {
		if err != syscall.Errno(0) {
			fmt.Printf("Error reading memory: %v\n", err)
		} else if numberOfBytesRead != uint32(len(buffer)) {
			fmt.Printf("Only partial memory was read: expected %d bytes, but read %d bytes\n", len(buffer), numberOfBytesRead)
		}
		return false
	}

	return true
}

func GetAddressFromOffsets(address uintptr, offsets ...uintptr) uintptr {
	if len(offsets) == 0 {
		return address
	}

	lastOffset := offsets[len(offsets)-1]
	offsets = offsets[:len(offsets)-1]
	return lastOffset + Pointer(address, offsets...)
}

func Pointer(address uintptr, offsets ...uintptr) uintptr {
	targetAddress := address
	for _, offset := range offsets {
		targetAddress = uintptr(unsafe.Pointer(uintptr(unsafe.Pointer(&targetAddress)) + offset))
	}
	return targetAddress
}
func GetProcessHandle(pid uint32) uintptr {
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	openProcessProc := kernel32.MustFindProc("OpenProcess")

	const (
		PROCESS_QUERY_INFORMATION = 0x0400
		PROCESS_VM_READ           = 0x0010
	)

	handle, _, _ := openProcessProc.Call(
		PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,
		uintptr(0),
		uintptr(pid),
	)

	if handle == 0 {
		return 0
	}

	return handle
}

func HexStringToPattern(hexString string) ([]string, error) {
	var aobPattern []string

	hexString = strings.ReplaceAll(hexString, " ", "")
	hexString = strings.ReplaceAll(hexString, "0x", "")

	wildcardCount := strings.Count(hexString, "?")

	if len(hexString) == 0 {
		return nil, fmt.Errorf("empty hex string")
	}

	if ContainsInvalidChars(hexString) {
		return nil, fmt.Errorf("hex string contains invalid characters")
	}

	if wildcardCount%2 != 0 {
		return nil, fmt.Errorf("odd number of wildcard characters")
	}

	if len(hexString)%2 != 0 {
		return nil, fmt.Errorf("hex string length is not even")
	}

	for i := 0; i < len(hexString); i += 2 {
		hexByte := hexString[i : i+2]
		if hexByte == "??" {
			aobPattern = append(aobPattern, "??")
		} else {
			aobPattern = append(aobPattern, hexByte)
		}
	}

	return aobPattern, nil
}

func ContainsInvalidChars(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') && c != '?' {
			return true
		}
	}
	return false
}

func SplitPath(path string) (string, string) {
	idx := strings.LastIndexByte(path, '\\')
	if idx == -1 {
		return "", path
	}
	return path[:idx], path[idx+1:]
}

func IsTarget64bit() (bool, error) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	isWow64ProcessProc := kernel32.NewProc("IsWow64Process")

	var isWow64 bool
	currentProcess, err := syscall.GetCurrentProcess()
	if err != nil {
		return false, err
	}

	_, _, err = isWow64ProcessProc.Call(
		uintptr(currentProcess),
		uintptr(unsafe.Pointer(&isWow64)),
	)
	if err != nil {
		return false, err
	}

	return !isWow64, nil
}
func ModulePatternScan(hProcess *uintptr, moduleName string, aobPattern ...string) (int64, error) {
	const (
		MEM_COMMIT    = 0x1000
		MEM_MAPPED    = 0x40000
		MEM_PRIVATE   = 0x20000
		PAGE_NOACCESS = 0x01
		PAGE_GUARD    = 0x100
	)

	var moduleInfo ModuleInfo
	var patternMask string
	var needleBuffer []byte
	var patternSize int
	if moduleName != "" {
		moduleInfo, _ = GetModuleInfo(pid, moduleName)
		fmt.Println(moduleInfo)
	} else {
		moduleInfo.lpBaseOfDll = 0
		moduleInfo.SizeOfImage = 0x7FFFFFFF
	}

	patternMask, needleBuffer, patternSize = GetNeedleFromAOBPattern(&aobPattern)
	if patternSize <= 0 {
		return 0, fmt.Errorf("invalid pattern size")
	}

	for address := moduleInfo.lpBaseOfDll; address < moduleInfo.lpBaseOfDll+uintptr(moduleInfo.SizeOfImage); {
		var memInfo MemoryInfo

		if !VirtualQueryEx(*hProcess, address, &memInfo) {
			//fmt.Printf("VirtualQueryEx failed for address: 0x%X\n", address)
			return 0, fmt.Errorf("VirtualQueryEx failed for address: 0x%X", address)
		}

		if memInfo.State == MEM_COMMIT &&
			(memInfo.Protect&(PAGE_NOACCESS|PAGE_GUARD) == 0) &&
			memInfo.RegionSize >= uintptr(patternSize) {

			result := PatternScan(hProcess, &address, &memInfo.RegionSize, patternMask, &needleBuffer)
			if result > 0 {
				return result, nil
			}
		}

		address += memInfo.RegionSize
	}

	return 0, fmt.Errorf("pattern not found")
}

func GetModuleInfo(processID uint32, moduleName string) (ModuleInfo, error) {
	var moduleInfo ModuleInfo

	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	module32NextProc := kernel32.MustFindProc("Module32NextW")
	module32FirstProc := kernel32.MustFindProc("Module32FirstW")
	createToolhelp32SnapshotProc := kernel32.MustFindProc("CreateToolhelp32Snapshot")

	snapshot, _, err := createToolhelp32SnapshotProc.Call(
		TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32,
		uintptr(processID),
	)
	if snapshot == uintptr(syscall.InvalidHandle) {
		return moduleInfo, fmt.Errorf("failed to create toolhelp32 snapshot: %v", err)
	}
	defer syscall.CloseHandle(syscall.Handle(snapshot))

	var me ModuleEntry32
	me.dwSize = uint32(unsafe.Sizeof(me))

	ret, _, err := module32FirstProc.Call(snapshot, uintptr(unsafe.Pointer(&me)))
	if ret == 0 {
		return moduleInfo, fmt.Errorf("failed to get first module: %v", err)
	}

	for {
		currentModuleName := syscall.UTF16ToString(me.szModule[:])
		//fmt.Printf("Checking module: %s\n", currentModuleName) // Debug log

		if strings.EqualFold(currentModuleName, moduleName) {
			moduleInfo.Name = currentModuleName
			moduleInfo.FileName = syscall.UTF16ToString(me.szExePath[:])
			moduleInfo.lpBaseOfDll = uintptr(me.modBaseAddr)
			moduleInfo.SizeOfImage = int(me.modBaseSize)
			moduleInfo.EntryPoint = uintptr(me.modBaseAddr)
			//fmt.Printf("Found module: %+v\n", moduleInfo) // Debug log
			return moduleInfo, nil
		}

		ret, _, err = module32NextProc.Call(snapshot, uintptr(unsafe.Pointer(&me)))
		if ret == 0 {
			break
		}
	}

	return moduleInfo, fmt.Errorf("module not found")
}

func HexStringToByteArray(hexString string) []byte {
	hexString = strings.ReplaceAll(hexString, " ", "")
	hexString = strings.ReplaceAll(hexString, "0x", "")

	byteArray := make([]byte, len(hexString)/2)
	for i := 0; i < len(hexString); i += 2 {
		val, _ := strconv.ParseInt(hexString[i:i+2], 16, 64)
		byteArray[i/2] = byte(val)
	}

	return byteArray
}

func WriteBytes(pid int, address uintptr, aobString string, offsets ...uintptr) error {
	aob := HexStringToByteArray(aobString)
	if offsets == nil {
		offsets = []uintptr{0x0}
	}
	fmt.Printf("Opening process with PID: %d\n %v", pid, aob)
	hProcess, _, err := openProcessProc.Call(
		uintptr(PROCESS_VM_WRITE|PROCESS_VM_OPERATION|PROCESS_VM_READ|PROCESS_QUERY_INFORMATION),
		uintptr(0),
		uintptr(uint32(pid)),
	)
	fmt.Println(err)
	if hProcess == 0 {
		return fmt.Errorf("failed to open process: %v", err)
	}
	defer syscall.CloseHandle(syscall.Handle(hProcess))

	targetAddress := GetAddressFromOffsets(address, offsets...)
	fmt.Printf("Target address: 0x%X\n", targetAddress)

	var numberOfBytesWritten uint32
	res, _, err := writeProcessMemory.Call(
		hProcess,
		targetAddress,
		uintptr(unsafe.Pointer(&aob[0])),
		uintptr(len(aob)),
		uintptr(unsafe.Pointer(&numberOfBytesWritten)),
	)

	if res == 0 {
		return fmt.Errorf("failed to write memory: %v", err)
	}

	if numberOfBytesWritten != uint32(len(aob)) {
		return fmt.Errorf("only partial memory was written: expected %d bytes, but wrote %d bytes", len(aob), numberOfBytesWritten)
	}

	return nil
}

func WriteRaw(pid int, address uintptr, buffer []byte, sizeBytes int, offsets ...uintptr) error {
	hProcess, _, err := openProcessProc.Call(
		uintptr(PROCESS_VM_WRITE|PROCESS_VM_OPERATION),
		uintptr(0),
		uintptr(uint32(pid)),
	)
	if err != nil {
		return fmt.Errorf("failed to open process: %v", err)
	}
	defer syscall.CloseHandle(syscall.Handle(hProcess))

	if hProcess == 0 {
		return fmt.Errorf("failed to open process")
	}

	targetAddress := GetAddressFromOffsets(address, offsets...)

	var numberOfBytesWritten uint32
	res, _, err := writeProcessMemory.Call(
		uintptr(hProcess),
		targetAddress,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(sizeBytes),
		uintptr(unsafe.Pointer(&numberOfBytesWritten)),
	)

	if res == 0 {
		return fmt.Errorf("failed to write memory: %v", err)
	}

	if numberOfBytesWritten != uint32(sizeBytes) {
		return fmt.Errorf("only partial memory was written: expected %d bytes, but wrote %d bytes", sizeBytes, numberOfBytesWritten)
	}

	return nil
}
