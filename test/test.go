package main

import (
    "fmt"
    "net"
    "flag"
    "io"
    "os"
    "strings"
    "strconv"
//    "reflect"
)

func server(listen string) {
    // listen on a port
    ln, err := net.Listen("tcp", listen)
    if err != nil {
         fmt.Println(err)
         return
    }
    defer ln.Close() 
    fmt.Println("Now listening on", listen)

    for {
        c, err := ln.Accept()
        if err != nil {
            fmt.Println(err)
            continue
        }

        go handleServerConnection(c)
    }
}

func addIpToTable(ip string) {
    ip = "127.0.0.1"
    ip = "127.1.80.1"

    fmt.Println(ip, "is ham:", isIpHam(ip))
}

func isIpHam(ip string) bool {

    if strings.Index(ip, ".") < 0 {
      // As we don't support IPv6 yet, it is all considered HAM
      return true
    }

    split_ip := strings.Split(ip, ".")
    rev_ip := strings.Join([]string{split_ip[3], split_ip[2], split_ip[1], split_ip[0]}, ".")

    host, err := net.LookupHost(fmt.Sprintf("configureme.%v.dnsbl.httpbl.org", rev_ip))
    if len(host) == 0 {
      fmt.Println("Received no result from httpbl.org:", err)
      return true
    }

    // Return value: "127", days gone stale, threat score, type (0 search engine, 1 suspicious, 2 harvester, 4 comment spammer)
    ret_octets := strings.Split(host[0], ".")
    if len(ret_octets) != 4 || ret_octets[0] != "127" {
      fmt.Println("Invalid return value from blacklist:", ret_octets)
      return true
    }

    stale_period,_ := strconv.Atoi(ret_octets[1])
    threat_score,_ := strconv.Atoi(ret_octets[2])
    score := (10/stale_period)*threat_score

    // Prefer it to be at least 10 days stale with a score of <25
    if stale_period > 10 {
      fmt.Println("Score for", ip, "is", score, "(threshold", 25, "), has gone stale with stale period", stale_period, " (stale threshold", 10, ") therefore considered no spam. Dnsbl retval:", host[0])
      return true
    }

//    fmt.Println("Calculated score for", ip, "based on", host[0], "is: ", score)
    if score > 25 {
      fmt.Println("Score for", ip, "is", score, "(threshold", 25, "), therefore considered spam. Dnsbl retval:", host[0])
      return false
    }

    fmt.Println("Score for", ip, "is", score, "(threshold", 25, "), therefore considered ham. Dnsbl retval:", host[0])
    return true
}

func handleServerConnection(c net.Conn) {
    defer c.Close()

    ip,_,_ := net.SplitHostPort(c.RemoteAddr().String())
    go addIpToTable(ip)

    for {
        msg := make([]byte, 1024)

        n, err := c.Read(msg)
        if err == io.EOF {
            fmt.Printf("[%v]: received EOF from %s (%d bytes ignored)\n", os.Getpid(), c.RemoteAddr(), n)
            return
        } else  if err != nil {
            fmt.Printf("[%v] ERROR while reading from %s: %s", os.Getpid(), c.RemoteAddr(), err)
            fmt.Print(err)
            return
        }
        fmt.Printf("[%v] received %v bytes from %s\n", os.Getpid(), n, c.RemoteAddr())

        n, err = c.Write(msg[:n])
        if err != nil {
            fmt.Printf("[%v] ERROR while writing to %s: %s", os.Getpid(), c.RemoteAddr(), err)
            return
        }
        fmt.Printf("[%v] sent %v bytes\n", os.Getpid(), n)
    }

}

func main() {

    listen := flag.String("listen", "[::1]:798", "Address:port to listen on")
    flag.Parse()

    go server(*listen)

    var input string
    fmt.Scanln(&input)
}
