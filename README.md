# What is this project?
This is a multi-threaded c++ implementation of the [dropbox content hash](https://www.dropbox.com/developers/reference/content-hash).

# Usage
Treat dbxhash as if it were the sha256sum executable. e.g.  
`dbxhash your_file_here`  
or
`pv -tpreb your_file_here | dbxhash`

# Build from source
## Install depenencies
### Debian
`apt-get update && apt-get install -y cmake g++ libssl-dev openssl libboost-all-dev`  

### Fedora
`dnf update -y && dnf install -y cmake g++ boost boost-devel`  

### build the source
`mkdir build; cd build`  
`cmake .. && make && make test`  
