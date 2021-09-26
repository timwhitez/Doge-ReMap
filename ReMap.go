package main

import (
	"crypto/sha1"
	"fmt"
	gabh "github.com/timwhitez/Doge-Gabh/pkg/Gabh"
	"strings"
	"syscall"
	"unsafe"

	"github.com/Binject/debug/pe"
	"github.com/awgh/rawreader"
	"golang.org/x/sys/windows"

)


func main(){
	//ntcreatefile = ac19c01d8c27c421e0b8a7960ae6bad2f84f0ce5
	NtCreateFile_ptr,_,e := gabh.GetFuncPtr("ntdll.dll","ac19c01d8c27c421e0b8a7960ae6bad2f84f0ce5",str2sha1)
	if e != nil{
		fmt.Println(e)
		return
	}


	var hNtdllfile uintptr

	ntdllPathW := "\\??\\C:\\Windows\\System32\\Ntdll.dll"
	ntdllPath , _ := windows.NewNTUnicodeString(ntdllPathW)

	objectAttributes := windows.OBJECT_ATTRIBUTES{}
	objectAttributes.Length = uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{}))
	objectAttributes.ObjectName = ntdllPath

	var ioStatusBlock windows.IO_STATUS_BLOCK

	//status = NtCreateFile(&handleNtdllDisk, FILE_READ_ATTRIBUTES | GENERIC_READ | SYNCHRONIZE, &objectAttributes, &ioStatusBlock, NULL, 0, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	syscall.Syscall12(uintptr(NtCreateFile_ptr),11,uintptr(unsafe.Pointer(&hNtdllfile)),uintptr(0x80|syscall.GENERIC_READ|syscall.SYNCHRONIZE),uintptr(unsafe.Pointer(&objectAttributes)),uintptr(unsafe.Pointer(&ioStatusBlock)),0,0,syscall.FILE_SHARE_READ,uintptr(0x00000001),uintptr(0x00000040|0x00000020),0,0,0)

	//ntcreatesection = 747d342b80e4c1c9d4d3dcb4ee2da24dcce27801
	NtCreateSection_ptr,_,_ := gabh.GetFuncPtr("ntdll.dll","747d342b80e4c1c9d4d3dcb4ee2da24dcce27801",str2sha1)

	var handleNtdllSection uintptr
	//status = NtCreateSection(&handleNtdllSection, STANDARD_RIGHTS_REQUIRED | SECTION_MAP_READ | SECTION_QUERY, NULL, NULL, PAGE_READONLY, SEC_IMAGE, handleNtdllDisk);
	syscall.Syscall9(uintptr(NtCreateSection_ptr),7, uintptr(unsafe.Pointer(&handleNtdllSection)),uintptr(0x000F0000|0x4|0x1),0,0,syscall.PAGE_READONLY,uintptr(0x1000000),hNtdllfile,0,0)


	//ntmapviewofsection = 7f346ebbd5dd0f0c2fc1f4a78f62615a64cab09a
	NtMapViewOfSection_ptr,_,_ := gabh.GetFuncPtr("ntdll.dll","7f346ebbd5dd0f0c2fc1f4a78f62615a64cab09a",str2sha1)

	var unhookedNtdllBaseAddress uintptr
	var size uintptr
	//status = NtMapViewOfSection(handleNtdllSection, NtCurrentProcess(), &unhookedNtdllBaseAddress, 0, 0, 0, &size, ViewShare, 0, PAGE_READONLY);
	syscall.Syscall12(uintptr(NtMapViewOfSection_ptr),10,handleNtdllSection,uintptr(0xffffffffffffffff),uintptr(unsafe.Pointer(&unhookedNtdllBaseAddress)),0,0,0,uintptr(unsafe.Pointer(&size)),1,0,syscall.PAGE_READONLY,0,0)

	NtDelayExecution_ptr,expname,e := GetFuncPtrR(unhookedNtdllBaseAddress,int(size),"NtDelayExecution")
	if e != nil{
		fmt.Println(e)
		return
	}
	fmt.Println(expname)
	times := -(10000 * 10000)
	syscall.Syscall(uintptr(NtDelayExecution_ptr),2,0,uintptr(unsafe.Pointer(&times)),0)

}



//GetFuncPtrR returns a pointer to the function (Virtual Address)
func GetFuncPtrR(phModule uintptr,Size int,funcname string) (uint64, string, error) {
	rr := rawreader.New(phModule, Size)
	p,e := pe.NewFileFromMemory(rr)
	if e != nil{
		return 0,"", e
	}

	ex,e := p.Exports()
	if e != nil{
		return 0,"", e
	}

	for _, exp := range ex {
		if strings.ToLower(exp.Name) == strings.ToLower(funcname) {
			return uint64(phModule) + uint64(exp.VirtualAddress), exp.Name,nil
		}
	}
	return 0,"", fmt.Errorf("could not find function!!! ")
}



func str2sha1(s string) string{
	h := sha1.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs)
}
