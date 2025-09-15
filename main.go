package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	certFile = flag.String("cert", "proxy-ca-cert.crt", "Path to the CA certificate file")
	keyFile  = flag.String("key", "proxy-ca-key.pem", "Path to the CA private key file")
	port     = flag.String("port", "8888", "Proxy port")
	verbose  = flag.Bool("v", true, "Verbose mode")

	caCert     *x509.Certificate
	caKey      *rsa.PrivateKey
	certCache  = make(map[string]*tls.Certificate)
	cacheMutex = &sync.RWMutex{}
)

func main() {
	flag.Parse()

	// 加载或生成CA证书
	if err := loadCA(); err != nil {
		log.Fatalf("Failed to load CA: %v", err)
	}

	// 启动代理服务器
	server := &http.Server{
		Addr: ":" + *port,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				handleHTTPS(w, r)
			} else {
				handleHTTP(w, r)
			}
		}),
	}

	log.Printf("Starting proxy server on port %s...", *port)
	log.Printf("CA Certificate: %s", *certFile)
	log.Printf("CA Private Key: %s", *keyFile)
	log.Fatal(server.ListenAndServe())
}

// 加载或生成CA证书
func loadCA() error {
	// 尝试加载现有的CA证书和私钥
	if _, err := os.Stat(*certFile); err == nil {
		if _, err := os.Stat(*keyFile); err == nil {
			// 加载现有的CA证书和私钥
			certData, err := os.ReadFile(*certFile)
			if err != nil {
				return fmt.Errorf("failed to read CA certificate: %v", err)
			}

			keyData, err := os.ReadFile(*keyFile)
			if err != nil {
				return fmt.Errorf("failed to read CA private key: %v", err)
			}

			// 解析证书
			block, _ := pem.Decode(certData)
			if block == nil {
				return fmt.Errorf("failed to parse CA certificate PEM")
			}

			caCert, err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				return fmt.Errorf("failed to parse CA certificate: %v", err)
			}

			// 解析私钥
			block, _ = pem.Decode(keyData)
			if block == nil {
				return fmt.Errorf("failed to parse CA private key PEM")
			}

			caKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				// 尝试PKCS8格式
				key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
				if err != nil {
					return fmt.Errorf("failed to parse CA private key: %v", err)
				}
				var ok bool
				caKey, ok = key.(*rsa.PrivateKey)
				if !ok {
					return fmt.Errorf("CA private key is not RSA")
				}
			}

			log.Printf("Loaded existing CA certificate (expires: %s)", caCert.NotAfter.Format("2006-01-02"))
			return nil
		}
	}

	// 生成新的CA证书和私钥
	log.Printf("Generating new CA certificate...")

	// 生成RSA私钥
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate CA private key: %v", err)
	}

	// 创建证书模板
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Go HTTPS Proxy CA",
			Organization: []string{"Go HTTPS Proxy"},
			Country:      []string{"CN"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(1, 0, 0), // 1年有效期
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// 自签名证书
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %v", err)
	}

	// 解析生成的证书
	caCert, err = x509.ParseCertificate(derBytes)
	if err != nil {
		return fmt.Errorf("failed to parse generated CA certificate: %v", err)
	}

	// 保存证书到文件
	certOut, err := os.Create(*certFile)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %v", *certFile, err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("failed to write CA certificate: %v", err)
	}

	// 保存私钥到文件
	keyOut, err := os.OpenFile(*keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %v", *keyFile, err)
	}
	defer keyOut.Close()

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %v", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return fmt.Errorf("failed to write CA private key: %v", err)
	}

	caKey = priv

	log.Printf("Generated new CA certificate (expires: %s)", template.NotAfter.Format("2006-01-02"))
	log.Printf("IMPORTANT: Install %s as a trusted root certificate in your client devices", *certFile)

	return nil
}

// 为目标主机生成证书
func generateCert(host string) (tls.Certificate, error) {
	// 从缓存中获取证书
	cacheMutex.RLock()
	if cert, exists := certCache[host]; exists {
		cacheMutex.RUnlock()
		return *cert, nil
	}
	cacheMutex.RUnlock()

	// 解析主机名（移除端口号）
	hostname := strings.Split(host, ":")[0]

	// 生成RSA私钥
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate private key for %s: %v", hostname, err)
	}

	// 创建证书模板
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: hostname,
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().AddDate(0, 0, 7), // 7天有效期
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		DNSNames: []string{hostname},
	}

	// 使用CA证书签名
	derBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create certificate for %s: %v", hostname, err)
	}

	// 创建TLS证书
	cert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}

	// 缓存证书
	cacheMutex.Lock()
	certCache[host] = &cert
	cacheMutex.Unlock()

	if *verbose {
		log.Printf("Generated certificate for: %s (expires: %s)", hostname, template.NotAfter.Format("2006-01-02"))
	}

	return cert, nil
}

// 处理HTTP请求 - 修复响应体读取问题
func handleHTTP(w http.ResponseWriter, r *http.Request) {
	if *verbose {
		log.Printf("HTTP Request: %s %s", r.Method, r.URL.String())
		log.Printf("Headers: %v", r.Header)

		// 记录请求体（如果有）
		if r.Body != nil && r.ContentLength > 0 {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				log.Printf("Error reading request body: %v", err)
			} else {
				log.Printf("Request Body: %s", string(body))
				// 重新设置请求体，以便后续使用
				r.Body = io.NopCloser(bytes.NewReader(body))
			}
		}
	}

	// 移除代理头
	r.RequestURI = ""
	r.Header.Del("Proxy-Connection")
	r.Header.Del("Proxy-Authenticate")
	r.Header.Del("Proxy-Authorization")

	// 发送请求到目标服务器
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // 不自动重定向
		},
	}

	resp, err := client.Do(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	if *verbose {
		log.Printf("HTTP Response: %s", resp.Status)
		log.Printf("Response Headers: %v", resp.Header)
	}

	// 读取响应体内容
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response body: %v", err)
		http.Error(w, "Failed to read response", http.StatusInternalServerError)
		return
	}

	if *verbose {
		log.Printf("Response Body: %s", string(bodyBytes))
	}

	// 重新设置响应体，以便后续读取
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	// 复制响应头
	for k, v := range resp.Header {
		for _, value := range v {
			w.Header().Add(k, value)
		}
	}

	w.WriteHeader(resp.StatusCode)

	// 复制响应体
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		log.Printf("Error writing response: %v", err)
	}
}

// 处理HTTPS请求
func handleHTTPS(w http.ResponseWriter, r *http.Request) {
	if *verbose {
		log.Printf("HTTPS CONNECT: %s", r.Host)
	}

	// 与目标服务器建立连接
	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer destConn.Close()

	// 告诉客户端连接已建立
	w.WriteHeader(http.StatusOK)

	// 获取底层连接
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	// 生成目标主机的证书
	cert, err := generateCert(r.Host)
	if err != nil {
		log.Printf("Failed to generate certificate for %s: %v", r.Host, err)
		return
	}

	// TLS配置
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	// 与客户端进行TLS握手
	tlsClientConn := tls.Server(clientConn, tlsConfig)
	if err := tlsClientConn.Handshake(); err != nil {
		log.Printf("TLS handshake with client failed: %v", err)
		return
	}
	defer tlsClientConn.Close()

	// 与目标服务器进行TLS握手
	tlsDestConn := tls.Client(destConn, &tls.Config{
		ServerName:         strings.Split(r.Host, ":")[0],
		InsecureSkipVerify: true, // 跳过证书验证
	})
	if err := tlsDestConn.Handshake(); err != nil {
		log.Printf("TLS handshake with destination failed: %v", err)
		return
	}
	defer tlsDestConn.Close()

	// 创建带缓冲的读写器来处理HTTPS流量解析
	clientReader := bufio.NewReader(tlsClientConn)

	for {
		// 读取客户端请求
		req, err := http.ReadRequest(clientReader)
		if err != nil {
			if err != io.EOF {
				log.Printf("Error reading HTTPS request: %v", err)
			}
			break
		}

		// 记录HTTPS请求详情
		if *verbose {
			log.Printf("HTTPS Request: %s %s", req.Method, req.URL.String())
			log.Printf("HTTPS Headers: %v", req.Header)

			if req.Body != nil && req.ContentLength > 0 {
				body, err := io.ReadAll(req.Body)
				if err != nil {
					log.Printf("Error reading HTTPS request body: %v", err)
				} else {
					log.Printf("HTTPS Request Body: %s", string(body))
					req.Body = io.NopCloser(bytes.NewReader(body))
				}
			}
		}

		// 转发请求到目标服务器
		req.URL.Scheme = "https"
		req.URL.Host = r.Host
		req.RequestURI = ""

		// 发送请求
		err = req.Write(tlsDestConn)
		if err != nil {
			log.Printf("Error writing to destination: %v", err)
			break
		}

		// 读取响应
		resp, err := http.ReadResponse(bufio.NewReader(tlsDestConn), req)
		if err != nil {
			log.Printf("Error reading response: %v", err)
			break
		}
		defer resp.Body.Close()

		// 记录HTTPS响应详情
		if *verbose {
			log.Printf("HTTPS Response: %s", resp.Status)
			log.Printf("HTTPS Response Headers: %v", resp.Header)

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				log.Printf("Error reading HTTPS response body: %v", err)
			} else {
				log.Printf("HTTPS Response Body: %s", string(body))
				resp.Body = io.NopCloser(bytes.NewReader(body))
			}
		}

		// 转发响应到客户端
		err = resp.Write(tlsClientConn)
		if err != nil {
			log.Printf("Error writing to client: %v", err)
			break
		}
	}
}

// 导出CA证书供客户端安装
func exportCACertificate() ([]byte, error) {
	if caCert == nil {
		return nil, fmt.Errorf("CA certificate not loaded")
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCert.Raw,
	}), nil
}
