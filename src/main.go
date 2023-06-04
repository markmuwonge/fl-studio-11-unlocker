package main

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fl-studio-11-unlocker/error"
	"log"
	"os"
	"strconv"

	peparser "github.com/saferwall/pe"

	"github.com/thoas/go-funk"
	"golang.org/x/sys/windows/registry"
)

const flEngineFileName = "FLEngine.dll"

var flEngineFileMd5Hashes = []string{"402f8aae4bfd1669f88340ff14a8262d"}

func main() {
	log.Println("FL Studio 11 Unlocker up...")

	key, err := registry.OpenKey(registry.CURRENT_USER, `SOFTWARE\Image-Line\Shared\Paths`, registry.QUERY_VALUE)
	error.Fatal(err)
	defer key.Close()

	directory, _, err := key.GetStringValue("0")
	error.Fatal(err)

	flEngineFileLocation := directory + "\\" + flEngineFileName
	log.Println("Reading", flEngineFileLocation)
	flEngineFileBytes, err := os.ReadFile(flEngineFileLocation)
	error.Fatal(err)

	recognized, flEngineFileMd5HashIndex := flEngineFileRecognized(flEngineFileBytes)
	if !recognized {
		error.Fatal(errors.New("File at " + flEngineFileLocation + " not recognized"))
	}
	log.Println(flEngineFileLocation, "matches hash at index", flEngineFileMd5HashIndex)

	peFile, err := peparser.NewBytes(flEngineFileBytes, &peparser.Options{})
	error.Fatal(err)

	log.Println("Parsing", flEngineFileLocation)
	err = peFile.Parse()
	error.Fatal(err)

	optionalHeader := peFile.NtHeader.OptionalHeader.(peparser.ImageOptionalHeader32)
	addressOfEntryPoint := optionalHeader.AddressOfEntryPoint
	log.Println(flEngineFileLocation, "address of entry point:", strconv.FormatInt(int64(addressOfEntryPoint), 16))

	sectionOptional := funk.Find(peFile.Sections, func(section peparser.Section) bool {
		sectionVirtualAddress := section.Header.VirtualAddress
		sectionEndVirtualAddress := (sectionVirtualAddress + section.Header.SizeOfRawData) - 1

		if addressOfEntryPoint >= sectionVirtualAddress && addressOfEntryPoint <= sectionEndVirtualAddress {
			return true
		} else {
			return false
		}
	})
	if sectionOptional == nil {
		error.Fatal(errors.New("Entry point section not found"))
	}
	section := sectionOptional.(peparser.Section)
	log.Println("Entry point section:", section.Header.Name)

	entryPointSectionOffset := addressOfEntryPoint - section.Header.VirtualAddress
	log.Println("Entry point section offset:", strconv.FormatInt(int64(entryPointSectionOffset), 16))

	entryPointFileOffset := section.Header.PointerToRawData + entryPointSectionOffset
	log.Println("Entry point file offset:", strconv.FormatInt(int64(entryPointFileOffset), 16))

	err = peFile.Close()
	error.Fatal(err)

	patchOneBytes := []byte{0xEB, 0x16, 0x90}
	for index, patchOneByte := range patchOneBytes {
		flEngineFileBytes[int(entryPointFileOffset)+index] = patchOneByte
	}
	log.Println("Patch one bytes written")

	patchTwoBytes := []byte{0x55, 0x90, 0x89, 0xE5, 0x51, 0x90, 0x81, 0xC1, 0xA0, 0x1D, 0x01, 0x00, 0x8B, 0x09, 0xC7, 0x01, 0x03, 0x00, 0x00, 0x00, 0x59, 0x90, 0xEB, 0xD3}
	for index, patchTwoByte := range patchTwoBytes {
		flEngineFileBytes[int(entryPointFileOffset)+0x18+index] = patchTwoByte
	}
	log.Println("Patch two bytes written")

	log.Println("Writing patched", flEngineFileName, "file")
	err = os.WriteFile(flEngineFileName, flEngineFileBytes, 0644)
	error.Warn(err)
	log.Println("Done")
}

func flEngineFileRecognized(flEngineFileRecognizedBytes []byte) (bool, int) {
	recognized := false
	hash := md5.Sum(flEngineFileRecognizedBytes)
	hashStr := hex.EncodeToString(hash[0:])

	index := funk.IndexOf(flEngineFileMd5Hashes, hashStr) // -1
	if index >= 0 {
		recognized = true
	}
	return recognized, index
}
