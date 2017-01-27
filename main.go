package main

import "log"
import "fmt"
import "time"
import "strings"
import "net"
import "io"
import "bytes"
import "os/exec"
import "io/ioutil"

import "crypto/tls"
import "crypto/sha1"
import "crypto/x509"
import "crypto/rsa"

import "net/http"
import "encoding/json"

type ScanData struct {
    Url          string
    Ip           string
    CommonName   string
    Subject      string
    Issuer       string
    ValidFrom    time.Time
    ValidTill    time.Time
    Fingerprint  string
    SignatureAlgorithm string
    PublicKeyAlgorithm string
    PublicN             string
    PublicE             int
}

func main() {
        http.HandleFunc("/", handle)
        //http.HandleFunc("/_ah/health", healthCheckHandler)
        http.HandleFunc("/scan", handleScan)
        log.Print("Listening on port 8080")
        log.Fatal(http.ListenAndServe(":8080", nil))
}
func handle(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path != "/" {
                http.NotFound(w, r)
                return
        }
        fmt.Fprint(w, "Hello world!!!!!")
}

func handleScan(w http.ResponseWriter, r *http.Request) {
        r.ParseForm()
        log.Print("Running SCAN!!" + r.FormValue("url"))
        analyzeDomain(r.FormValue("url"), w);

        log.Print("Running NMAP")
        if cmd, e := exec.Run("nmap --script ssl-enum-ciphers -p 443 " + r.FormValue("url"), nil, nil, exec.DevNull, exec.Pipe, exec.MergeWithStdout); e == nil {
            b, _ := ioutil.ReadAll(cmd.Stdout)
            fmt.Fprint(w, string(b))
        }

        fmt.Fprint(w, "\n\n END\n")
}

func storeCertificate(domain string, ip string, cert *x509.Certificate, w http.ResponseWriter) {
    // Fingerprint Sha1
    hash := sha1.New()
    hash.Write(cert.Raw)

    scan := &ScanData{
        Url:                domain,
        Ip:                 ip,
        CommonName:         string(cert.Subject.CommonName),
        Subject:            cert.Subject.Organization[0],
        Issuer:             cert.Issuer.Organization[0],
        ValidFrom:          cert.NotBefore,
        ValidTill:          cert.NotAfter,
        Fingerprint:        fmt.Sprintf("%X \n", hash.Sum(nil)),
        SignatureAlgorithm: cert.SignatureAlgorithm.String(),
        PublicKeyAlgorithm: getPKAName(cert.PublicKeyAlgorithm),
        PublicN:            cert.PublicKey.(*rsa.PublicKey).N.String(),
        PublicE:            cert.PublicKey.(*rsa.PublicKey).E,
    };
    json, _ := json.Marshal(scan)

    fmt.Fprint(w, string(json))


    response, err := http.Post("http://reconscan-154715.appspot.com/store", "application/json", bytes.NewBuffer(json))
    if err != nil {
            log.Fatal(err)
    } else {
            defer response.Body.Close()

            fmt.Fprint(w, response.Status)

    }



    /*
    //block := &pem.Block{"CERTIFICATE", nil, cert.Raw}
    // Common name
    fmt.Println(string(cert.Subject.CommonName));

    fmt.Println(cert.Subject.Organization);

    fmt.Println(cert.Issuer.Organization);

    // Valid Range
    fmt.Println(cert.NotBefore.String());
    fmt.Println(cert.NotAfter.String());


    fmt.Println(cert.DNSNames);
    fmt.Println(cert.IPAddresses);
    fmt.Println(cert.EmailAddresses);







    // Signature Algorithm
    fmt.Println(cert.SignatureAlgorithm.String());

    // PK Algorithm
    fmt.Println("Public Key Algorithm: " + getPKAName(cert.PublicKeyAlgorithm));


    fmt.Printf("Version: %d \n", cert.Version);

    // Public Modulus
    fmt.Println(cert.PublicKey.(*rsa.PublicKey).N);
    fmt.Println(BitCount(cert.PublicKey.(*rsa.PublicKey).N));


    fmt.Println(cert.PublicKey.(*rsa.PublicKey).E);


    fmt.Printf("\n %x \n", cert.Signature);
*/
/*
    key := datastore.NewIncompleteKey(ctx, "scan", nil)
    if _, err := datastore.Put(ctx, key, scan); err != nil {
          io.WriteString(w, err.Error());
    }
*/
    //fmt.Printf(string(pem.EncodeToMemory(block)))

}

func getPKAName(n x509.PublicKeyAlgorithm) string {
    switch n {
        case 1:
            return "RSA";
        case 2:
            return "DSA";
        case 3:
            return "ECDSA";
    }
    return "UNKNOWN"
}



func analyzeDomain(domain string, w http.ResponseWriter) {
    var httpsDomain string
    var httpDomain string

    if ! strings.Contains(domain, ":") {
        httpsDomain = domain + ":443"
        httpDomain = domain + ":80"
    }
    dialer := net.Dialer{}
    dialer.Timeout = 10 * time.Second
    conn, err := tls.DialWithDialer(&dialer, "tcp", httpsDomain, &tls.Config{
        InsecureSkipVerify: true,
    })
    if err != nil {
        io.WriteString(w, fmt.Sprintf("failed to connect to %s %s", httpsDomain, err.Error()))
        //fmt.Println(fmt.Sprintf("\x1b[31;1mfailed to connect to %s", domain), err, "\x1b[0m")
        return
    }

    defer conn.Close()
    for _, cert := range conn.ConnectionState().PeerCertificates {
        storeCertificate(domain, conn.RemoteAddr().String(), cert, w)
    }

    fmt.Fprint(w, "\n\n")
    c, err := net.Dial("tcp", httpDomain)
    if err != nil {
    	// handle error
    }

    fmt.Fprint(w, c.RemoteAddr().String())
    c.Close()
}
