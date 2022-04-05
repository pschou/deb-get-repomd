// Written by Paul Schou (paulschou.com) March 2022
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type Repomd struct {
	Header            map[string]string
	Data              map[string]*RepoHashFile
	fileContents      []byte
	gpgFileContents   string
	gpgInFileContents string
	path              string
	mirror            string
	Timestamp         time.Time
}

type RepoHashFile struct {
	Checksum     []string
	ChecksumType []string
	Size         int
}

var client = http.Client{
	Timeout: 5 * time.Second,
}

func readRepomdFile(repomdFile string) *Repomd {
	// Declare file handle for the reading
	var file io.Reader

	if _, err := os.Stat(repomdFile); err == nil {
		log.Println("Reading in file", repomdFile)

		// Open our xmlFile
		rawFile, err := os.Open(repomdFile)
		if err != nil {
			log.Println("Error in HTTP get request", err)
			return nil
		}

		// Make sure the file is closed at the end of the function
		defer rawFile.Close()
		file = rawFile
	} else if strings.HasPrefix(repomdFile, "http") {
		resp, err := client.Get(repomdFile)
		if err != nil {
			log.Println("Error in HTTP get request", err)
			return nil
		}

		defer resp.Body.Close()
		file = resp.Body
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(file)
	contents := buf.Bytes()

	var dat = Repomd{
		Header: make(map[string]string),
		Data:   make(map[string]*RepoHashFile),
	}

	scanner := bufio.NewScanner(bytes.NewReader(contents))
	var section, line string
	for scanner.Scan() {
		line = scanner.Text()
		//fmt.Println("line:", line)
		if strings.HasPrefix(line, " ") {
			parts := strings.Fields(strings.TrimSpace(line))
			if len(parts) != 3 {
				fmt.Println("Invalid file section", line)
				return nil
			}
			size, err := strconv.Atoi(parts[1])
			if err != nil {
				fmt.Println("Invalid file size", parts[1])
				return nil
			}
			if current, exist := dat.Data[parts[2]]; exist {
				current.Checksum = append(current.Checksum, parts[0])
				current.ChecksumType = append(current.ChecksumType, section)
				if size != current.Size {
					log.Println("Error in decoding Release file: mismatching file size", size, current.Size)
					return nil
				}
			} else {
				dat.Data[parts[2]] = &RepoHashFile{Checksum: []string{parts[0]}, ChecksumType: []string{section}, Size: size}
			}
		} else {
			parts := strings.SplitN(strings.TrimSpace(line), ":", 2)
			if len(parts) != 2 {
				log.Println("Error in decoding Release file header")
				return nil
			}
			if val := strings.TrimSpace(parts[1]); val == "" {
				section = parts[0]
			} else {
				dat.Header[parts[0]] = val
			}
		}
	}

	if val, ok := dat.Header["Date"]; ok {
		tval, err := time.Parse(time.RFC1123, val)
		if err != nil {
			fmt.Println("Invalid date format", val)
			return nil
		}
		dat.Timestamp = tval
	}

	dat.fileContents = contents

	return &dat
}

func readWithChecksum(fileName, checksum, checksumType string) *[]byte {
	// Declare file handle for the reading
	var file io.Reader

	if _, err := os.Stat(fileName); err == nil {
		log.Println("Reading in file", fileName)

		// Open our xmlFile
		rawFile, err := os.Open(fileName)
		if err != nil {
			log.Println("Error in opening file locally", err)
			return nil
		}

		// Make sure the file is closed at the end of the function
		defer rawFile.Close()
		file = rawFile
	} else if strings.HasPrefix(fileName, "http") {
		resp, err := client.Get(fileName)
		if err != nil {
			log.Println("Error in HTTP get request", err)
			return nil
		}

		defer resp.Body.Close()
		file = resp.Body
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(file)
	contents := buf.Bytes()
	var sum string

	switch strings.ToLower(checksumType) {
	case "md5sum":
		sum = fmt.Sprintf("%x", md5.Sum(contents))
	case "sha1":
		sum = fmt.Sprintf("%x", sha1.Sum(contents))
	case "sha256":
		sum = fmt.Sprintf("%x", sha256.Sum256(contents))
	case "sha512":
		sum = fmt.Sprintf("%x", sha512.Sum512(contents))
	}

	if sum == checksum {
		//fmt.Println("sum", sum, checksum)
		return &contents
	}
	return nil
}
