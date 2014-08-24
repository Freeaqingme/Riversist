package main

import (
    "bytes"
    "flag"
    "fmt"
//    "gcfg"
    "io"
    "net"
    "os"
    "os/signal"
    "os/exec"
    "reflect"
    "strconv"
    "strings"
    "syscall"
    "test/log"
    "unsafe"
)

var logger log.Logger


func main() {

    setProcessName("riversist")

    listen := flag.String("listen", "[::1]:798", "Address:port to listen on")
    logLevel := flag.Int("loglevel", 5, "Syslog Loglevel (0-7, Emerg-Debug)")
    flag.Parse()

    logger = logger.New(*logLevel)
    logger.Log(log.LOG_NOTICE, "Starting...")
    defer logger.Log(log.LOG_CRIT, "Exiting...")

    sig := make(chan bool)
    loop := make(chan error)

    go sigHandler(sig)
    go server(*listen, loop)

    for quit := false; !quit; {
        select {
             case quit = <-sig:
             case <-loop:
        }
    }

}



// We make sigHandler receive a channel on which we will report the value of var quit
func sigHandler(q chan bool) {
    var quit bool

    c := make(chan os.Signal, 1)
    signal.Notify(c, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

    for signal := range c {
        logger.Log(log.LOG_NOTICE, "Received signal: "+signal.String())

        switch signal {
            case syscall.SIGINT, syscall.SIGTERM:
                quit = true
            case syscall.SIGHUP:
                quit = false
        }

        if quit {
            quit = false
            logger.Log(log.LOG_CRIT, "Terminating...")
            //              closeDb()
            //              closeLog()
            os.Exit(0)
       }
       // report the value of quit via the channel
       q <- quit
    }
}

func server(listen string, loop chan error) {

    ln, err := net.Listen("tcp", listen)
    if err != nil {
         logger.Fatal(err.Error())
    }
    defer ln.Close() 
    logger.Log(log.LOG_INFO, "Now listening on", listen)

    for {
        loop <- nil

        c, err := ln.Accept()
        if err != nil {
            logger.Log(log.LOG_WARNING, string(err.Error()))
            continue
        }

        go handleServerConnection(c)
    }
}

func setProcessName(name string) error {
    argv0str := (*reflect.StringHeader)(unsafe.Pointer(&os.Args[0]))
    argv0 := (*[1 << 30]byte)(unsafe.Pointer(argv0str.Data))[:argv0str.Len]

    paddedName := fmt.Sprintf("%-" + strconv.Itoa(len(argv0)) + "s", name)
    if len(paddedName) > len(argv0) {
      panic("Cannot set proccess name that is longer than original argv[0]")
    }

    n := copy(argv0, paddedName)
    if n < len(argv0) {
        argv0[n] = 0
    }

    return nil
}

func handleServerConnection(c net.Conn) {
    defer c.Close()

    ip,_,_ := net.SplitHostPort(c.RemoteAddr().String())
    go addIpToTable(ip)

    for {
        msg := make([]byte, 1024)

        n, err := c.Read(msg)
        if err == io.EOF {
            logger.Log(log.LOG_DEBUG, fmt.Sprintf("received EOF from %s (%d bytes ignored)", c.RemoteAddr(), n))
            return
        } else  if err != nil {
            logger.Log(log.LOG_INFO, fmt.Sprintf("ERROR while reading from %s: %s", c.RemoteAddr(), err))
            return
        }
        logger.Log(log.LOG_DEBUG, fmt.Sprintf("received %v bytes from %s", n, c.RemoteAddr()))

/*        n, err = c.Write(msg[:n])
        if err != nil {
            logger.Log(syslog.LOG_INFO, fmt.Sprintf("ERROR while writing to %s: %s", c.RemoteAddr(), err))
            return
        }
        logger.Log(syslog.LOG_DEBUG, fmt.Sprintf("Sent %v bytes to %s\n", n, c.RemoteAddr()))
*/
    }

}


func addIpToTable(ip string) {
    ip = "127.0.0.1"
    ip = "127.1.80.1"

    var cmdStr string
    if isIpHam(ip) {
        cmdStr = "/home/dolf/Projects/Go/addIpToTable ham %s"
    } else {
        cmdStr = "/home/dolf/Projects/Go/addIpToTable spam %s"
    }

    cmdStr = fmt.Sprintf(cmdStr, ip)
    cmdArr := strings.Split(cmdStr, " ")
    cmd := exec.Command(cmdArr[0], cmdArr[1:len(cmdArr)]...)

    var out bytes.Buffer
    cmd.Stdout = &out
    err := cmd.Run()
    if err != nil {
        logger.Log(log.LOG_ERR, "Could not execute " + cmdStr + ": ", err.Error())
    }

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
      logger.Log(log.LOG_DEBUG, "Received no result from httpbl.org:", err.Error())
      return true
    }

    // Return value: "127", days gone stale, threat score, type (0 search engine, 1 suspicious, 2 harvester, 4 comment spammer)
    ret_octets := strings.Split(host[0], ".")
    if len(ret_octets) != 4 || ret_octets[0] != "127" {
      logger.Log(log.LOG_INFO, "Invalid return value from httpbl.org:", string(host[0]))
      return true
    }

    stale_period,_ := strconv.Atoi(ret_octets[1])
    threat_score,_ := strconv.Atoi(ret_octets[2])
    score := (10/stale_period)*threat_score

    // Prefer it to be at least 10 days stale with a score of <25
    if stale_period > 14 {
      logger.Log(log.LOG_INFO, "DNSBL: httpbl.org, IP:", ip, ", score:", strconv.Itoa(score), ", threshold:", strconv.Itoa(25), ", verdict: stale, stale_period:", strconv.Itoa(stale_period), ", stale_threshold: ", strconv.Itoa(14), " verdict: ham, dnsbl_retval: ", host[0])
      return true
    }

    if score > 25 {
      logger.Log(log.LOG_INFO, "DNSBL: httpbl.org, IP:", ip, " score:", strconv.Itoa(score), ", threshold:", strconv.Itoa(25), ", verdict: spam, dnsbl_retval:", host[0])
      return false
    }

    logger.Log(log.LOG_INFO, "DNSBL: httpbl.org, IP:", ip, " score:", strconv.Itoa(score), ", threshold:", strconv.Itoa(25), ", verdict: ham, dnsbl_retval:", host[0])
    return true
}
