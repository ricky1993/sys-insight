package utils

import (
	"bufio"
	"os"
)

func ReadLines(file string) ([]string, error) {
	return readLines(file, os.O_RDONLY)
}

func ReadLinesCreateIfNotExists(file string) ([]string, error) {
	return readLines(file, os.O_RDWR|os.O_CREATE)
}

func readLines(file string, mode int) ([]string, error) {
	lines := make([]string, 0)
	f, err := os.OpenFile(file, mode, 0600)
	if err != nil {
		return lines, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return lines, err
	}
	return lines, nil
}
