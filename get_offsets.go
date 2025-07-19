package main

import (
	"debug/elf"
	"fmt"
	"io"
	"runtime"
	"strings"

	"github.com/knightsc/gapstone"
	"github.com/mandiant/GoReSym/buildid"
	"github.com/mandiant/GoReSym/buildinfo"
	"github.com/mandiant/GoReSym/debug/gosym"
	"github.com/mandiant/GoReSym/objfile"
	"github.com/mandiant/GoReSym/runtime/debug"
)

// pclntab header info
type PcLnTabMetadata struct {
	VA            uint64
	Version       string
	Endianess     string
	CpuQuantum    uint32
	CpuQuantumStr string
	PointerSize   uint32
}

type FuncMetadata struct {
	Start       uint64
	End         uint64
	PackageName string
	FullName    string
}

type ExtractMetadata struct {
	Version       string
	BuildId       string
	Arch          string
	OS            string
	TabMeta       PcLnTabMetadata
	ModuleMeta    objfile.ModuleData
	Types         []objfile.Type
	Interfaces    []objfile.Type
	BuildInfo     debug.BuildInfo
	Files         []string
	UserFunctions []FuncMetadata
	StdFunctions  []FuncMetadata
}

type SymbolData struct {
	Symbol string
	Vaddr uint64
	Offset uint64
	Exits []uint64 
}

var extractMetadata = ExtractMetadata{};

func GetOffsets(fileName string, targetSymbol string) (SymbolData, error) {
	file, err := objfile.Open(fileName)
	if err != nil {
		return SymbolData{}, fmt.Errorf("invalid file: %w", err)
	}

	buildId, err := buildid.ReadFile(fileName)
	if err == nil {
		extractMetadata.BuildId = buildId
	} else {
		extractMetadata.BuildId = ""
	}

	// try to get version the 'correct' way, also fill out buildSettings if parsing was ok
	bi, err := buildinfo.ReadFile(fileName)
	if err == nil {
		extractMetadata.Version = bi.GoVersion

		for _, setting := range bi.Settings {
			if setting.Key == "GOOS" {
				extractMetadata.OS = setting.Value
			} else if setting.Key == "GOARCH" {
				extractMetadata.Arch = setting.Value
			}
		}

		extractMetadata.BuildInfo = *bi
	}

	var knownPclntabVA = uint64(0)
	var knownGoTextBase = uint64(0)

	restartParseWithRealTextBase:
		ch_tabs, err := file.PCLineTable("", knownPclntabVA, knownGoTextBase)
		if err != nil {
			return SymbolData{}, fmt.Errorf("failed to read pclntab: %w", err)
		}

		var moduleData *objfile.ModuleData = nil
		var finalTab *objfile.PclntabCandidate = nil
		for tab := range ch_tabs {

			// numeric only, go1.17 -> 1.17
			goVersionIdx := strings.Index(extractMetadata.Version, "go")
			if goVersionIdx != -1 {
				// "devel go1.18-2d1d548 Tue Dec 21 03:55:43 2021 +0000"
				extractMetadata.Version = strings.Split(extractMetadata.Version[goVersionIdx+2:]+" ", " ")[0]

				// go1.18-2d1d548
				extractMetadata.Version = strings.Split(extractMetadata.Version+"-", "-")[0]
			}

			extractMetadata.TabMeta.CpuQuantum = tab.ParsedPclntab.Go12line.Quantum

			// quantum is the minimal unit for a program counter (1 on x86, 4 on most other systems).
			// 386: 1, amd64: 1, arm: 4, arm64: 4, mips: 4, mips/64/64le/64be: 4, ppc64/64le: 4, riscv64: 4, s390x: 2, wasm: 1
			extractMetadata.TabMeta.CpuQuantumStr = "x86/x64/wasm"
			if extractMetadata.TabMeta.CpuQuantum == 2 {
				extractMetadata.TabMeta.CpuQuantumStr = "s390x"
			} else if extractMetadata.TabMeta.CpuQuantum == 4 {
				extractMetadata.TabMeta.CpuQuantumStr = "arm/mips/ppc/riscv"
			}

			extractMetadata.TabMeta.VA = tab.PclntabVA
			extractMetadata.TabMeta.Version = tab.ParsedPclntab.Go12line.Version.String()
			extractMetadata.TabMeta.Endianess = tab.ParsedPclntab.Go12line.Binary.String()
			extractMetadata.TabMeta.PointerSize = tab.ParsedPclntab.Go12line.Ptrsize

			// this can be a little tricky to locate and parse properly across all go versions
			// since moduledata holds a pointer to the pclntab, we can (hopefully) find the right candidate by using it to find the moduledata.
			// if that location works, then we must have given it the correct pclntab VA. At least in theory...
			// The resolved offsets within the pclntab might have used the wrong base though! We'll fix that later.
			_, tmpModData, err := file.ModuleDataTable(tab.PclntabVA, extractMetadata.Version, extractMetadata.TabMeta.Version, extractMetadata.TabMeta.PointerSize == 8, extractMetadata.TabMeta.Endianess == "LittleEndian")
			if err == nil && tmpModData != nil {
				// if the search candidate relied on a moduledata va, make sure it lines up with ours now
				stomppedMagicMetaConstraintsValid := true
				if tab.StompMagicCandidateMeta != nil {
					stomppedMagicMetaConstraintsValid = tab.StompMagicCandidateMeta.SuspectedModuleDataVa == tmpModData.VA
				}

				if knownGoTextBase == 0 && knownPclntabVA == 0 && stomppedMagicMetaConstraintsValid {
					// assign real base and restart pclntab parsing with correct VAs!
					knownGoTextBase = tmpModData.TextVA
					knownPclntabVA = tab.PclntabVA
					goto restartParseWithRealTextBase
				}

				// we already have pclntab candidates with the right VA, but which candidate?? The one that finds a valid moduledata!
				finalTab = &tab
				moduleData = tmpModData
				break
			}
		}

	if finalTab == nil {
		return SymbolData{}, fmt.Errorf("no valid pclntab found")
	}

	// to be sure we got the right pclntab we had to have found a moduledat as well. If we didn't, then we failed to find the pclntab (correctly) as well
	if moduleData == nil {
		return SymbolData{}, fmt.Errorf("no valid moduledata found")
	}

	extractMetadata.ModuleMeta = *moduleData
	types, _ := file.ParseTypeLinks(extractMetadata.Version, moduleData, extractMetadata.TabMeta.PointerSize == 8, extractMetadata.TabMeta.Endianess == "LittleEndian")
	extractMetadata.Types = types

	var sym *gosym.Sym; 
	for _, elem := range finalTab.ParsedPclntab.Funcs {
		if elem.Name == targetSymbol {
			sym = elem.Sym;
			break
		}
	}

	if sym != nil {
		// Open the ELF file.
		f, err := elf.Open(fileName)

		// Return with error if file can't be opened
		if err != nil {
			return SymbolData{}, fmt.Errorf("error analyzing file for the given symbols")
		}
		defer f.Close()

		textSection := f.Section(".text")
		if textSection == nil {
			err = fmt.Errorf("no text section")
			return SymbolData{}, err
		}

		textSectionFile := textSection.Open()

		var lastProg *elf.Prog;
		var fileOffset uint64;

		// Iterate over the program segments to calculate the file offset from the virtual address of the symbol
		for _, prog := range f.Progs {
			
			// Skip non-loadable or non-executable segments.
			if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
				continue
			}

			// Check if the symbol's address is inside the current segment.
			if prog.Vaddr <= uint64(sym.Value) && sym.Value < (prog.Vaddr+prog.Memsz) {
				// Adjust the address to the file offset.
				fileOffset = sym.Value - prog.Vaddr + prog.Off
				lastProg = prog;
				_ = fileOffset;
				break;
				// return sym.Value, fileOffset, []uint64{}, nil
			}
		}

		if fileOffset <= 0 {
			return SymbolData{}, fmt.Errorf("error analyzing file for the given symbols")
		}

		symStartingIndex := sym.Value - textSection.Addr
		symEndingIndex := symStartingIndex + (sym.Func.End - sym.Func.Entry)

		// collect the bytes of the symbol
		textSectionDataLen := uint64(textSection.Size - 1)
		if symEndingIndex > textSectionDataLen {
			fmt.Printf(
				"Error: Symbol %v, ending index %v is bigger than text section data length %v",
				sym.Name,
				symEndingIndex,
				textSectionDataLen,
			)
			return SymbolData{}, fmt.Errorf("error analyzing file for the given symbols")
		}

		if _, err = textSectionFile.Seek(int64(symStartingIndex), io.SeekStart); err != nil {
			return SymbolData{}, fmt.Errorf("error analyzing file for the given symbols")
		}

		num := int(symEndingIndex - symStartingIndex)
		var numRead int
		symBytes := make([]byte, num)
		numRead, err = textSectionFile.Read(symBytes)
		if err != nil {
			return SymbolData{}, fmt.Errorf("error analyzing file for the given symbols")
		}
		if numRead != num {
			return SymbolData{}, fmt.Errorf("error analyzing file for the given symbols")
		}

		var engine gapstone.Engine
		switch runtime.GOARCH {
		case "amd64":
			engine, err = gapstone.New(
				gapstone.CS_ARCH_X86,
				gapstone.CS_MODE_64,
			)
		case "arm64":
			engine, err = gapstone.New(
				gapstone.CS_ARCH_ARM64,
				gapstone.CS_MODE_LITTLE_ENDIAN,
			)
		default:
			err = fmt.Errorf("unsupported architecture: %v", runtime.GOARCH)
		}
		if err != nil {
			return SymbolData{}, fmt.Errorf("error analyzing file for the given symbols")
		}
	
		engineMajor, engineMinor := engine.Version()
		fmt.Printf(
			"Disassembling %s with Capstone %d.%d (arch: %d, mode: %d)\n",
			fileName,
			engineMajor,
			engineMinor,
			engine.Arch(),
			engine.Mode(),
		)

		// disassemble the symbol
		var instructions []gapstone.Instruction
		instructions, err = engine.Disasm(symBytes, sym.Value, 0)
		if err != nil {
			return SymbolData{}, fmt.Errorf("error analyzing file for the given symbols")
		}

		var exits []uint64;
		// iterate over each instruction and if the mnemonic is `ret` then that's an exit offset
		for _, ins := range instructions {
			if ins.Mnemonic == "ret" {
				exits = append(exits, uint64(ins.Address)-lastProg.Vaddr+lastProg.Off)
			}
		}

		return SymbolData{Symbol: sym.Name, Vaddr: sym.Value, Offset: fileOffset, Exits: exits},nil
	}

	return SymbolData{}, fmt.Errorf("error analyzing file for the given symbols")
}