# iron-go [![Build Status](https://travis-ci.org/WatchBeam/iron-go.svg?branch=master)](https://travis-ci.org/WatchBeam/iron-go) [![godoc reference](https://godoc.org/github.com/WatchBeam/iron-go?status.png)](https://godoc.org/github.com/WatchBeam/iron-go)


iron-go is an implementation of [Iron](https://github.com/hueniverse/iron) cookies for Go. It's fully inter-operable with the Node version. Currently it supports sealing and unsealing using a single secret key, but it should be fairly trivial to implement rotation in the future. <sup>[Citation Needed]</sup>


```go
v := iron.New(Options{Secret: password})

// encrypt your cookie:

cookie, err := v.Seal(yourData)

// Later....

payload, err := v.Unseal(cookie)

// Use your data!
```
