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
	"bytes"
	"compress/gzip"
	"flag"
	"fmt"
	"hash"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

var version = "test"

var makeTree *bool

// Main is a function to fetch the HTTP repodata from a URL to get the latest
// package list for a repo
func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Debian Get Repo Metadata,  Version: %s\n\nUsage: %s [options...]\n\n", version, os.Args[0])
		flag.PrintDefaults()
	}

	var inRepoPath = flag.String("repo", "dists/stable/main/binary-amd64", "Repo path to use in fetching")
	var mirrorList = flag.String("mirrors", "mirrorlist.txt", "Mirror / directory list of prefixes to use")
	var outputPath = flag.String("output", ".", "Path to put the repodata files")
	var insecure = flag.Bool("insecure", false, "Skip signature checks")
	makeTree = flag.Bool("tree", false, "Make repo tree (recommended, provides gpg and InRelease files)")
	var keyringFile = flag.String("keyring", "keys/", "Use keyring for verifying, keyring.gpg or keys/ directory")
	flag.Parse()

	mirrors := readMirrors(*mirrorList)
	repoPath := strings.TrimSuffix(strings.TrimPrefix(*inRepoPath, "/"), "/")

	var latestRepomd Repomd
	var latestRepomdTime int64
	var keyring openpgp.EntityList
	if !*insecure {
		var err error
		if _, ok := isDirectory(*keyringFile); ok {
			//keyring = openpgp.EntityList{}
			for _, file := range getFiles(*keyringFile, ".gpg") {
				//fmt.Println("loading key", file)
				gpgFile := readFile(file)
				fileKeys, err := loadKeys(gpgFile)
				if err != nil {
					log.Fatal("Error loading keyring file", err)
				}
				//fmt.Println("  found", len(fileKeys), "keys")
				keyring = append(keyring, fileKeys...)
			}
		} else {
			gpgFile := readFile(*keyringFile)
			keyring, err = loadKeys(gpgFile)
			if err != nil {
				log.Fatal("Error loading keyring file", err)
			}
		}
		if len(keyring) == 0 {
			log.Fatal("no keys loaded")
		}
	}

	repoPath = "/" + repoPath
	repoPathBottom2 := getBottomDir(repoPath, 2)
	repoPathUpper := strings.TrimPrefix(repoPath, repoPathBottom2+"/")

	var mu sync.Mutex
	var wg sync.WaitGroup

	for j, mm := range mirrors {
		i := j
		wg.Add(1)
		go func(m string) {
			defer wg.Done()
			//repomdPath := m + repoPath + "Packages.gz"
			releasePath := m + repoPathBottom2 + "/Release"
			releasePathGPG := releasePath + ".gpg"
			releasePathInGPG := m + repoPathBottom2 + "/InRelease"
			log.Println(i, "Fetching", releasePath)

			dat := readRepomdFile(releasePath, m)
			mu.Lock()
			defer mu.Unlock()
			if dat != nil {
				fmt.Println("  found timestamp", dat.Timestamp.Unix(), "in", releasePath)
				if dat.Timestamp.Unix() > latestRepomdTime {
					if !*insecure {
						// Verify gpg signature file
						log.Println("Fetching signature file:", releasePathGPG)
						gpgFile := readFile(releasePathGPG)
						signature_block, err := armor.Decode(strings.NewReader(gpgFile))
						if err != nil {
							log.Println("Unable decode signature")
							return
						}
						p, err := packet.Read(signature_block.Body)
						if err != nil {
							log.Println("Unable parse signature")
							return
						}
						var signed_at time.Time
						var issuerKeyId uint64
						var hash hash.Hash

						switch sig := p.(type) {
						case *packet.Signature:
							issuerKeyId = *sig.IssuerKeyId
							signed_at = sig.CreationTime
							if hash == nil {
								hash = sig.Hash.New()
							}
						case *packet.SignatureV3:
							issuerKeyId = sig.IssuerKeyId
							signed_at = sig.CreationTime
							if hash == nil {
								hash = sig.Hash.New()
							}
						default:
							fmt.Println("Signature block is invalid")
							return
						}

						if issuerKeyId == 0 {
							fmt.Println("Signature doesn't have an issuer")
							return
						}

						if keyring == nil {
							fmt.Printf("  %s - Signed by 0x%02X at %v\n", releasePathGPG, issuerKeyId, signed_at)
							os.Exit(1)
						} else {
							fmt.Printf("Verifying %s has been signed by 0x%02X at %v...\n", releasePathGPG, issuerKeyId, signed_at)
						}
						keys := keyring.KeysByIdUsage(issuerKeyId, packet.KeyFlagSign)

						if len(keys) == 0 {
							fmt.Println("error: No matching public key found to verify")
							return
						}
						if len(keys) > 1 {
							fmt.Println("warning: More than one public key found matching KeyID")
						}

						dat.gpgFileContents = gpgFile
						fmt.Println("GPG Verified!")
						dat.gpgInFileContents = readFile(releasePathInGPG)
					}
					if latestRepomdTime == 0 {
						log.Println("using first")
					} else {
						log.Println("found newer")
					}
					//readFile(releasePathGPG)
					dat.path = releasePath
					dat.mirror = m
					latestRepomd = *dat
					latestRepomdTime = dat.Timestamp.Unix()
				}
			}
		}(mm)
		time.Sleep(70 * time.Millisecond)
	}
	wg.Wait()
	fmt.Println("Using mirror at", latestRepomd.mirror)

	var byHash bool
	if t, ok := latestRepomd.Header["Acquire-By-Hash"]; ok && t == "yes" {
		byHash = true
	}
	fmt.Println("Acquire-By-Hash is", byHash)

	//log.Printf("latest: %+v", latestRepomd)
	trylist := []string{latestRepomd.mirror}
	trylist = append(trylist, mirrors...)

	outputPathFull := *outputPath
	if *makeTree {
		outputPathFull = path.Join(*outputPath, *inRepoPath)
	}

	// Create the directory if needed
	err := ensureDir(outputPathFull)
	if err != nil {
		log.Fatal("Could not create the directory", err)
	}

	// Flags to help us avoid downloading an uncompressed version of Packages
	var hasPackagesGZ, hasPackages bool
	//var packagesMeta RepoHashFile
	for filePath, _ := range latestRepomd.Data {
		if strings.HasPrefix(filePath, repoPathUpper) {
			if strings.HasSuffix(filePath, "/Packages.gz") {
				hasPackagesGZ = true
			}
			if strings.HasSuffix(filePath, "/Packages") {
				hasPackages = true
				//packagesMeta = *meta
			}
		}
	}
	byHashDir := path.Join(outputPathFull, "by-hash")
	if !(hasPackagesGZ || hasPackages) {
		fmt.Println("Note: Make sure your \"repo\" is set to the child path under the mirror URL with the file containing Packages.gz")
	}

RepoMdFile:
	for filePath, meta := range latestRepomd.Data {
		//fmt.Println(path, repoPathUpper)
		if strings.HasPrefix(filePath, repoPathUpper) {
			// skip the downloading uncompressed file
			if hasPackagesGZ && strings.HasSuffix(filePath, "/Packages") {
				continue
			}

			for _, tryMirror := range trylist {
				fileURL := tryMirror + repoPathBottom2 + "/" + filePath
				fmt.Println("getting", fileURL)
				//, meta.Checksum[len(meta.Checksum)-1], meta.ChecksumType[len(meta.ChecksumType)-1])
				fileData := readWithChecksum(fileURL,
					meta.Checksum[len(meta.Checksum)-1],
					meta.ChecksumType[len(meta.ChecksumType)-1])
				if fileData == nil {
					fmt.Println("  trying a different mirror")
					continue
				}
				// Write out the file
				_, file := path.Split(fileURL)
				outFile := path.Join(outputPathFull, file)
				writeFile(outFile, fileData, latestRepomd.Timestamp)

				if byHash {
					for j, ckSumType := range meta.ChecksumType {
						ckSumDir := path.Join(byHashDir, ckSumType)
						ensureDir(ckSumDir)
						outFile := path.Join(ckSumDir, meta.Checksum[j])
						writeFile(outFile, fileData, latestRepomd.Timestamp)
					}
				}

				if err == nil {
					if strings.HasSuffix(filePath, "/Packages.gz") && hasPackages {
						outFile = path.Join(outputPathFull, strings.TrimSuffix(file, ".gz"))
						writeUncompressedFile(outFile, fileData, latestRepomd.Timestamp)

						// Don't need to waste space if we don't need this file
						/*
							if byHash {
								for j, ckSumType := range packagesMeta.ChecksumType {
									ckSumDir := path.Join(byHashDir, ckSumType)
									ensureDir(ckSumDir)
									outFile := path.Join(ckSumDir, packagesMeta.Checksum[j])
									writeUncompressedFile(outFile, fileData, latestRepomd.Timestamp)
								}
							}
						*/

					}
					continue RepoMdFile
				}
			}

		}
	}
	if *makeTree {
		outputBottomTwo := path.Join(*outputPath, repoPathBottom2)
		// Write out the repomd file into the path
		{
			outFile := path.Join(outputBottomTwo, "Release")
			f, err := os.Create(outFile)
			if err != nil {
				log.Fatal(err)
			}
			_, err = f.Write(latestRepomd.fileContents)
			if err != nil {
				log.Fatal("Cannot write Release", err)
			}
			f.Close()
			timestamp := time.Unix(latestRepomdTime, 0)
			os.Chtimes(outFile, timestamp, timestamp)
		}

		// If we have a signature file, write it out
		if len(latestRepomd.gpgFileContents) > 0 {
			outFile := path.Join(outputBottomTwo, "Release.gpg")
			f, err := os.Create(outFile)
			if err != nil {
				log.Fatal(err)
			}
			_, err = f.Write([]byte(latestRepomd.gpgFileContents))
			if err != nil {
				log.Fatal("Cannot write Release.gpg", err)
			}
			f.Close()
			timestamp := time.Unix(latestRepomdTime, 0)
			os.Chtimes(outFile, timestamp, timestamp)
		}

		if len(latestRepomd.gpgInFileContents) > 0 {
			outFile := path.Join(outputBottomTwo, "InRelease")
			f, err := os.Create(outFile)
			if err != nil {
				log.Fatal(err)
			}
			_, err = f.Write([]byte(latestRepomd.gpgInFileContents))
			if err != nil {
				log.Fatal("Cannot write InRelease", err)
			}
			f.Close()
			timestamp := time.Unix(latestRepomdTime, 0)
			os.Chtimes(outFile, timestamp, timestamp)
		}
	}
}

func writeFile(outFile string, fileData *[]byte, Timestamp time.Time) {
	fmt.Println("writing", outFile)
	f, err := os.Create(outFile)
	if err != nil {
		log.Fatal(err)
	}
	_, err = f.Write(*fileData)
	f.Close()
	os.Chtimes(outFile, Timestamp, Timestamp)
}

func writeUncompressedFile(outFile string, fileData *[]byte, Timestamp time.Time) {
	fmt.Println("writing comp", outFile)
	f_uncompress, err := os.Create(outFile)
	if err != nil {
		log.Fatal(err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(*fileData))
	if err != nil {
		log.Fatal(err)
	}
	io.Copy(f_uncompress, gz)
	gz.Close()
	f_uncompress.Close()
	os.Chtimes(outFile, Timestamp, Timestamp)
}

func check(e error) {
	if e != nil {
		//panic(e)
		log.Fatal(e)
	}
}

// isDirectory determines if a file represented
// by `path` is a directory or not
func isDirectory(path string) (exist bool, isdir bool) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false, false
	}
	return true, fileInfo.IsDir()
}

func getFiles(walkdir, suffix string) []string {
	ret := []string{}
	err := filepath.Walk(walkdir,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				fmt.Println(err)
				return err
			}
			if !info.IsDir() && strings.HasSuffix(path, suffix) {
				ret = append(ret, path)
			}
			return nil
		})
	if err != nil {
		log.Fatal(err)
	}
	return ret
}
