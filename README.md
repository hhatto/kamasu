# kamasu [![](https://travis-ci.org/hhatto/kamasu.svg?branch=master)](https://travis-ci.org/hhatto/kamasu)

HTTP Proxy Sever for PHP Built-in Server, written in Rust.

```
        +---------------------+         +----------------------------------------+
        |  kamasu(main proc)  | - - - - |                                        |-+
        |                     |  +----> |           php built-in server          | |-+
  HTTP  |    +--------+  HTTP |  |+---> | (child proc via std::process::Command) | | |
 ----------->| thread |----------+|     |                                        | | |
        |    | (http) |       |   |     +----------------------------------------+ | |
        |    +---------       |   |       +----------------------------------------+ |
        |                     |   |         +----------------------------------------+
  H2/HTTPS   +--------+  HTTP |   |                         :
 ----------->| thread |-----------+                         : N procs
        |    | (https)|       |                             :
        |    +--------+       |
        |                     |
        +---------------------+
```

## Installation

```
$ cargo install --git https://github.com/hhatto/kamasu.git
```

## Usage

with HTTP:
```
$ kamasu -S 127.0.0.1:8080 -n 4 -t /your/docroot -c php.ini
```

with H2(HTTPS):
```
$ kamasu --https 127.0.0.1:8443 -n 4 -t /your/docroot -c php.ini
```

## License

Copyright 2017- Hideo Hattori

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
