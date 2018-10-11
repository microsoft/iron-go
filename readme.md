# iron-go [![Build Status](https://travis-ci.org/mixer/iron-go.svg?branch=master)](https://travis-ci.org/mixer/iron-go) [![godoc reference](https://godoc.org/github.com/mixer/iron-go?status.png)](https://godoc.org/github.com/mixer/iron-go)


iron-go is an implementation of [Iron](https://github.com/hueniverse/iron) cookies for Go. It's fully inter-operable with the Node version. Currently it supports sealing and unsealing using a single secret key, but it should be fairly trivial to implement rotation in the future. <sup>[Citation Needed]</sup>


```go
v := iron.New(Options{Secret: password})

// encrypt your cookie:

cookie, err := v.Seal(yourData)

// Later....

payload, err := v.Unseal(cookie)

// Use your data!
```
### CLI

iron-go includes a simple CLI to seal and unseal cookies. Install via:

```
go install github.com/WatchBeam/iron-go/cmd/iron
```

Usage example:

```
➜  iron-go git:(master) iron --help
usage: iron --secret=SECRET [<flags>] <command> [<args> ...]

Flags:
      --help           Show context-sensitive help (also try --help-long and --help-man).
  -s, --secret=SECRET  Cookie encryption password
  -v, --value=VALUE    Cookie contents. If not provided, reads from stdin.

Commands:
  help [<command>...]
    Show help.

  seal
    Encrypts the cookie

  unseal
    Decrypts the cookie


➜  iron-go git:(master) pbpaste | iron unseal --secret=somethingatleast32characterslong
{"hello":"world!"}
```
