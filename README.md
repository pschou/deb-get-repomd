# Debian Get Repo MetaData Utility

This shim fetches a Debian repo metadata from a given repo and mirror list.  It
verifies the PGP signature and checksums of each file to ensure integrity.

# Example usage:
```bash
./deb-get-repomd -mirrors mirrorlist.txt -repo dists/Debian11.2/main/binary-amd64 -keyring keys/ -output test
```

and the output looks like:
```
$ ./deb-get-repomd -output test
CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=0.1.20220323.2107" -o "deb-get-repomd" main.go repomd.go filelib.go loadKeys.go
2022/03/23 21:07:10 Reading in file keys/debian11.gpg
  1) Loaded KeyID: 0xDC30D7C23CBBABEE
2022/03/23 21:07:10 0 Fetching http://ftp.us.debian.org/debian/dists/Debian11.2/Release
2022/03/23 21:07:11 Fetching signature file: http://ftp.us.debian.org/debian/dists/Debian11.2/Release.gpg
Verifying http://ftp.us.debian.org/debian/dists/Debian11.2/Release.gpg has been signed by 0x648ACFD622F3D138 at 2021-12-18 05:39:50 -0500 EST...
GPG Verified!
2022/03/23 21:07:11 1 Fetching http://atl.mirrors.clouvider.net/debian/dists/Debian11.2/Release
2022/03/23 21:07:11 2 Fetching http://debian-archive.trafficmanager.net/debian/dists/Debian11.2/Release
2022/03/23 21:07:11 3 Fetching http://debian.cc.lehigh.edu/debian/dists/Debian11.2/Release
2022/03/23 21:07:11 4 Fetching http://debian.csail.mit.edu/debian/dists/Debian11.2/Release
2022/03/23 21:07:11 5 Fetching http://debian.cs.binghamton.edu/debian/dists/Debian11.2/Release
2022/03/23 21:07:11 6 Fetching http://debian.ec.as6453.net/debian/dists/Debian11.2/Release
2022/03/23 21:07:12 7 Fetching http://debian.gtisc.gatech.edu/debian/dists/Debian11.2/Release
2022/03/23 21:07:12 8 Fetching http://debian.mirror.constant.com/debian/dists/Debian11.2/Release
2022/03/23 21:07:12 9 Fetching http://debian.osuosl.org/debian/dists/Debian11.2/Release
2022/03/23 21:07:12 10 Fetching http://debian.uchicago.edu/debian/dists/Debian11.2/Release
2022/03/23 21:07:12 11 Fetching http://la.mirrors.clouvider.net/debian/dists/Debian11.2/Release
2022/03/23 21:07:13 12 Fetching http://mirror.cogentco.com/debian/dists/Debian11.2/Release
2022/03/23 21:07:13 13 Fetching http://mirror.keystealth.org/debian/dists/Debian11.2/Release
2022/03/23 21:07:13 14 Fetching http://mirror.pit.teraswitch.com/debian/dists/Debian11.2/Release
2022/03/23 21:07:13 15 Fetching http://mirrors.accretive-networks.net/debian/dists/Debian11.2/Release
2022/03/23 21:07:14 16 Fetching http://mirrors.advancedhosters.com/debian/dists/Debian11.2/Release
2022/03/23 21:07:14 17 Fetching http://mirrors.bloomu.edu/debian/dists/Debian11.2/Release
2022/03/23 21:07:14 18 Fetching http://mirrors.edge.kernel.org/debian/dists/Debian11.2/Release
2022/03/23 21:07:14 19 Fetching http://mirrors.gigenet.com/debian/dists/Debian11.2/Release
2022/03/23 21:07:14 20 Fetching http://mirror.siena.edu/debian/dists/Debian11.2/Release
2022/03/23 21:07:14 21 Fetching http://mirrors.lug.mtu.edu/debian/dists/Debian11.2/Release
2022/03/23 21:07:14 22 Fetching http://mirrors.ocf.berkeley.edu/debian/dists/Debian11.2/Release
2022/03/23 21:07:15 23 Fetching http://mirror.steadfast.net/debian/dists/Debian11.2/Release
2022/03/23 21:07:15 24 Fetching http://mirrors.vcea.wsu.edu/debian/dists/Debian11.2/Release
2022/03/23 21:07:15 25 Fetching http://mirrors.wikimedia.org/debian/dists/Debian11.2/Release
2022/03/23 21:07:15 26 Fetching http://mirrors.xtom.com/debian/dists/Debian11.2/Release
2022/03/23 21:07:16 27 Fetching http://mirror.us.leaseweb.net/debian/dists/Debian11.2/Release
2022/03/23 21:07:16 28 Fetching http://mirror.us.oneandone.net/debian/dists/Debian11.2/Release
2022/03/23 21:07:16 29 Fetching http://nyc.mirrors.clouvider.net/debian/dists/Debian11.2/Release
2022/03/23 21:07:16 30 Fetching http://plug-mirror.rcac.purdue.edu/debian/dists/Debian11.2/Release
2022/03/23 21:07:16 31 Fetching http://repo.ialab.dsu.edu/debian/dists/Debian11.2/Release
2022/03/23 21:07:16 32 Fetching http://us.mirror.nsec.pt/debian/dists/Debian11.2/Release
getting http://ftp.us.debian.org/debian/dists/Debian11.2/main/binary-amd64/Release
getting http://ftp.us.debian.org/debian/dists/Debian11.2/main/binary-amd64/Packages.xz
getting http://ftp.us.debian.org/debian/dists/Debian11.2/main/binary-amd64/Packages.gz

$ ls test
Packages.gz  Packages.xz  Release
```


# Usage help:
```bash
$ ./deb-get-repomd -h
Debian Get Repo Metadata,  Version: 0.1.20220323.2107

Usage: ./deb-get-repomd [options...]

  -insecure
        Skip signature checks
  -keyring string
        Use keyring for verifying, keyring.gpg or keys/ directory (default "keys/")
  -mirrors string
        Mirror / directory list of prefixes to use (default "mirrorlist.txt")
  -output string
        Path to put the repodata files (default ".")
  -repo string
        Repo path to use in fetching (default "dists/Debian11.2/main/binary-amd64")
```




