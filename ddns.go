package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const Prefix string = "2409"                                    // 【pay attention to modify】telecom: 240e; unicon:2408; mobile:2409
const RR string = "@"                                           // 【pay attention to modify】
const DomainName string = "xxxxxx.xxxxxx"                       // 【pay attention to modify】
const AccessKeyId string = "xxxxxxxxxxxxxxxxxxxxxxxx"           // 【pay attention to modify】
const AccessSecret string = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"    // 【pay attention to modify】
const LogPath string = "/var/services/homes/shaw/Host/ddns.log" // 【pay attention to modify】

func encodeURIComponent(str string) string {
	r := url.QueryEscape(str)
	r = strings.Replace(r, "+", "%20", -1)
	r = strings.Replace(r, "%7E", "~", -1)
	return r
}

func Base64_HMACSHA1(keyStr, value string) string {
	key := []byte(keyStr)
	mac := hmac.New(sha1.New, key)
	mac.Write([]byte(value))
	res := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return res
}

func main() {
	var RecordId string
	var IPV6 string
	var RetryTime int
	LogFile, err := os.OpenFile(LogPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		return
	}

	log.SetOutput(LogFile)
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Printf("net.InterfaceAddrs err(%v) occured\n", err)
		return
	}
	for _, addr := range addrs {
		pattern, err := regexp.Compile(`(` + Prefix + `(:\w+){7})/64`)
		if err != nil {
			log.Printf("regexp.Compile err(%v) occured\n", err)
			return
		}
		ret := pattern.FindStringSubmatch(addr.String())
		if ret != nil {
			IPV6 = ret[1]
			break
		}
	}
	log.Printf("IPV6: %v\n", IPV6)

	for RetryTime = 0; RetryTime < 10; RetryTime++ {
		SignatureNonce := strconv.FormatInt(time.Now().Unix(), 10)
		gmt := time.FixedZone("GMT", 0)
		Timestamp := time.Now().In(gmt).Format("2006-01-02T15:04:05Z")
		CanonicalizedQueryString := "AccessKeyId=" + AccessKeyId + "&Action=DescribeDomainRecords&DomainName=" + DomainName + "&SignatureMethod=HMAC-SHA1&SignatureNonce=" + SignatureNonce + "&SignatureVersion=1.0&Timestamp=" + encodeURIComponent(Timestamp) + "&Version=2015-01-09"
		StringtoSign := "GET&%2F&" + encodeURIComponent(CanonicalizedQueryString)
		Signature := Base64_HMACSHA1(AccessSecret+"&", StringtoSign)
		req := "https://alidns.aliyuncs.com/?" + CanonicalizedQueryString + "&Signature=" + encodeURIComponent(Signature)
		res, err := http.Get(req)
		if err != nil {
			log.Printf("err(%v) occured, retrying...\n", err)
			time.Sleep(10 * time.Second)
			continue
		}
		body, err := io.ReadAll(res.Body)
		if err != nil {
			log.Printf("err(%v) occured, retrying...\n", err)
			time.Sleep(10 * time.Second)
			continue
		}
		pattern, err := regexp.Compile(`<RR>` + RR + `</RR>.*?<RecordId>(\d*)</RecordId>`)
		if err != nil {
			log.Printf("err(%v) occured, retrying...\n", err)
			time.Sleep(10 * time.Second)
			continue
		}
		ret := pattern.FindStringSubmatch(string(body))
		if ret == nil {
			log.Println("failed to find RecordId, retrying...")
			time.Sleep(10 * time.Second)
			continue
		}
		RecordId = ret[1]
		pattern, err = regexp.Compile(`<RR>` + RR + `</RR>.*?<Value>(.*)</Value>`)
		if err != nil {
			log.Printf("err(%v) occured, retrying...\n", err)
			time.Sleep(10 * time.Second)
			continue
		}
		ret = pattern.FindStringSubmatch(string(body))
		if ret == nil {
			log.Println("failed to find IPV6 Value, retrying...")
			time.Sleep(10 * time.Second)
			continue
		}
		if ret[1] == IPV6 {
			log.Println("IPV6 not changed")
			return
		}
		break
	}
	for RetryTime = 0; RetryTime < 10; RetryTime++ {
		SignatureNonce := strconv.FormatInt(time.Now().Unix(), 10)
		gmt := time.FixedZone("GMT", 0)
		Timestamp := time.Now().In(gmt).Format("2006-01-02T15:04:05Z")
		CanonicalizedQueryString := "AccessKeyId=" + AccessKeyId + "&Action=UpdateDomainRecord&RR=" + encodeURIComponent(RR) + "&RecordId=" + RecordId + "&SignatureMethod=HMAC-SHA1&SignatureNonce=" + SignatureNonce + "&SignatureVersion=1.0&Timestamp=" + encodeURIComponent(Timestamp) + "&Type=AAAA&Value=" + encodeURIComponent(IPV6) + "&Version=2015-01-09"
		StringtoSign := "GET&%2F&" + encodeURIComponent(CanonicalizedQueryString)
		Signature := Base64_HMACSHA1(AccessSecret+"&", StringtoSign)
		req := "https://alidns.aliyuncs.com/?" + CanonicalizedQueryString + "&Signature=" + encodeURIComponent(Signature)
		res, err := http.Get(req)
		if err != nil {
			log.Printf("err(%v) occured, retrying...\n", err)
			time.Sleep(10 * time.Second)
			continue
		}
		body, err := io.ReadAll(res.Body)
		if err != nil {
			log.Printf("err(%v) occured, retrying...\n", err)
			time.Sleep(10 * time.Second)
			continue
		}
		if strings.Contains(string(body), "<Code>DomainRecordDuplicate</Code>") {
			log.Println("the DNS record already exists.")
			break
		}
		pattern, err := regexp.Compile(`<RecordId>(\d*)</RecordId>`)
		if err != nil {
			log.Printf("err(%v) occured, retrying...\n", err)
			time.Sleep(10 * time.Second)
			continue
		}
		ret := pattern.FindStringSubmatch(string(body))
		if ret == nil {
			log.Println("failed to find RecordId, retrying...")
			time.Sleep(10 * time.Second)
			continue
		}
		if ret[1] == RecordId {
			log.Println("succeed to modify record")
		}
		break
	}
}
