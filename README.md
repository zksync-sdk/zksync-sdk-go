# ZKSyncSDK for Go

  Cryptographical primitives used in zkSync network.


## Requirements

- macOS 10.12+ / linux x86_64 / windows x86_64
- go >= 1.15
- libzkscrypto.a


## Installation

* Import package to your project (use flag `-d` to prevent compiling attempt):
  
  `go get -d github.com/zksync-sdk/zksync-sdk-go`
* Download binary library for your platform from https://github.com/zksync-sdk/zksync-crypto-c/releases, change downloaded file name to `libzks-crypto` (but keep original file extension) and put it into `./libs` directory of your project
* Build project, using `CGO_LDFLAGS="-L./libs"` environment variable:
  
  `CGO_LDFLAGS="-L./libs" go build`
  
  or just export it for current environment:
  
  ```
  $ export CGO_LDFLAGS="-L./libs"
  $ go build
  ```


## License

The MIT License (MIT)

Copyright (c) 2020 Matter Labs

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.