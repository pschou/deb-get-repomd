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
	"flag"
	"fmt"
	"hash"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

var version = "test"

// Main is a function to fetch the HTTP repodata from a URL to get the latest
// package list for a repo
func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Debian Get Repo Metadata,  Version: %s\n\nUsage: %s [options...]\n\n", version, os.Args[0])
		flag.PrintDefaults()
	}

	var inRepoPath = flag.String("repo", "dists/Debian11.2/main/binary-amd64", "Repo path to use in fetching")
	var mirrorList = flag.String("mirrors", "mirrorlist.txt", "Mirror / directory list of prefixes to use")
	var outputPath = flag.String("output", ".", "Path to put the repodata files")
	var insecure = flag.Bool("insecure", false, "Skip signature checks")
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

	for i, m := range mirrors {
		//repomdPath := m + repoPath + "Packages.gz"
		releasePath := m + repoPathBottom2 + "/Release"
		releasePathGPG := releasePath + ".gpg"
		log.Println(i, "Fetching", releasePath)

		dat := readRepomdFile(releasePath)
		if dat != nil {
			if dat.Timestamp.Unix() > latestRepomdTime {
				if !*insecure {
					// Verify gpg signature file
					log.Println("Fetching signature file:", releasePathGPG)
					gpgFile := readFile(releasePathGPG)
					signature_block, err := armor.Decode(strings.NewReader(gpgFile))
					if err != nil {
						log.Println("Unable decode signature")
						continue
					}
					p, err := packet.Read(signature_block.Body)
					if err != nil {
						log.Println("Unable parse signature")
						continue
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
						continue
					}

					if issuerKeyId == 0 {
						fmt.Println("Signature doesn't have an issuer")
						continue
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
						continue
					}
					if len(keys) > 1 {
						fmt.Println("warning: More than one public key found matching KeyID")
						continue
					}

					dat.ascFileContents = gpgFile
					fmt.Println("GPG Verified!")
				}
				if latestRepomdTime != 0 {
					log.Println("found newer")
				}
				readFile(releasePathGPG)
				dat.path = releasePath
				dat.mirror = m
				latestRepomd = *dat
				latestRepomdTime = dat.Timestamp.Unix()
			}
		}
	}

	//log.Printf("latest: %+v", latestRepomd)
	trylist := []string{latestRepomd.mirror}
	trylist = append(trylist, mirrors...)

	// Create the directory if needed
	err := ensureDir(*outputPath)
	if err != nil {
		log.Fatal(err)
	}

	var hasPackagesGZ bool
	for filePath, _ := range latestRepomd.Data {
		//fmt.Println(path, repoPathUpper)
		if strings.HasPrefix(filePath, repoPathUpper) &&
			strings.HasSuffix(filePath, "/Packages.gz") {
			hasPackagesGZ = true
		}
	}

RepoMdFile:
	for filePath, meta := range latestRepomd.Data {
		//fmt.Println(path, repoPathUpper)
		if strings.HasPrefix(filePath, repoPathUpper) {
			// skip the uncompressed file!
			if hasPackagesGZ && strings.HasSuffix(filePath, "/Packages") {
				continue
			}

			for _, tryMirror := range trylist {
				fileURL := tryMirror + repoPathBottom2 + "/" + filePath
				fmt.Println("getting", fileURL)
				fileData := readWithChecksum(fileURL, meta.Checksum, meta.ChecksumType)
				if fileData != nil {
					//fmt.Println("length", len(*fileData))
					//u, err := url.Parse(fileURL)
					//if err != nil {
					//	continue
					//}
					_, file := path.Split(fileURL)
					f, err := os.Create(path.Join(*outputPath, file))
					if err != nil {
						log.Fatal(err)
					}
					defer f.Close()
					_, err = f.Write(*fileData)
					if err == nil {
						continue RepoMdFile
					}
				}
			}

		}
	}
	/*
	   	// Write out the repomd file into the path
	   	{
	   		f, err := os.Create(path.Join(*outputPath, "repomd.xml"))
	   		if err != nil {
	   			log.Fatal(err)
	   		}
	   		defer f.Close()
	   		_, err = f.Write(latestRepomd.fileContents)
	   		if err != nil {
	   			log.Fatal("Cannot write repomd.xml", err)
	   		}
	   	}

	   	// If we have a signature file, write it out
	   	if len(latestRepomd.ascFileContents) > 0 {
	   		f, err := os.Create(path.Join(*outputPath, "repomd.xml.asc"))
	   		if err != nil {
	   			log.Fatal(err)
	   		}
	   		defer f.Close()
	   		_, err = f.Write(latestRepomd.fileContents)
	   		if err != nil {
	   			log.Fatal("Cannot write repomd.xml", err)
	   		}
	   	}

	   RepoMdFile:
	   	for _, filePath := range latestRepomd.Data {
	   		for _, tryMirror := range trylist {
	   			fileURL := tryMirror + "/" + repoPath + "/" + strings.TrimPrefix(filePath.Location.Href, "/")
	   			fmt.Println("getting", fileURL)
	   			fileData := readWithChecksum(fileURL, filePath.Checksum.Text, filePath.Checksum.Type)
	   			if fileData != nil {
	   				//fmt.Println("length", len(*fileData))
	   				//u, err := url.Parse(fileURL)
	   				//if err != nil {
	   				//	continue
	   				//}
	   				_, file := path.Split(fileURL)
	   				f, err := os.Create(path.Join(*outputPath, file))
	   				if err != nil {
	   					log.Fatal(err)
	   				}
	   				defer f.Close()
	   				_, err = f.Write(*fileData)
	   				if err == nil {
	   					continue RepoMdFile
	   				}
	   			}
	   		}
	   	}
	*/

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
