package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	kopis "github.com/HicaroD/kopis"
)

func main() {
	format := flag.String("format", "terminal", "output format: terminal or jsonl")
	input := flag.String("input", "-", "JSON ScanResult input, or - for standard input")
	flag.Parse()

	reader := io.Reader(os.Stdin)
	var file *os.File
	if *input != "-" {
		var err error
		file, err = os.Open(*input)
		if err != nil {
			fmt.Fprintln(os.Stderr, "kopis: unable to read input")
			os.Exit(1)
		}
		defer file.Close()
		reader = file
	}
	var result kopis.ScanResult
	if err := json.NewDecoder(reader).Decode(&result); err != nil {
		fmt.Fprintln(os.Stderr, "kopis: invalid scan result")
		os.Exit(1)
	}

	var err error
	switch *format {
	case "terminal":
		err = kopis.WriteTerminal(os.Stdout, result)
	case "jsonl":
		err = kopis.WriteJSONL(os.Stdout, result)
	default:
		fmt.Fprintln(os.Stderr, "kopis: format must be terminal or jsonl")
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "kopis: output failed")
		os.Exit(1)
	}
	os.Exit(kopis.ExitCode(result))
}
