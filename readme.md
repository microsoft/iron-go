# iron-go

iron-go is an implementation of [Iron](https://github.com/hueniverse/iron) cookies for Go. It's fully inter-operable with the Node version. Currently it just supports unsealing using a single secret key, but it should be fairly trivial to implement sealing and rotation in the future. <sup>[Citation Needed]</sup>


```go
v := iron.New(Options{Secret: password})
payload, err := v.Unseal(yourCookie)

// unmarshal the payload JSON as you see fit!
```
