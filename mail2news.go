package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/viper"
	"golang.org/x/net/proxy"
)

// Config structure to hold all configuration
type Config struct {
	Paths      PathsConfig      `mapstructure:"paths"`
	NNTP       NNTPConfig       `mapstructure:"nntp"`
	Thresholds ThresholdsConfig `mapstructure:"thresholds"`
	Logging    LoggingConfig    `mapstructure:"logging"`
}

type PathsConfig struct {
	Log     string `mapstructure:"log"`
	Etc     string `mapstructure:"etc"`
	Lib     string `mapstructure:"lib"`
	History string `mapstructure:"history"`
}

type NNTPConfig struct {
	Path           string `mapstructure:"path_header"`
	InjectionHost  string `mapstructure:"injection_host"`
	Contact        string `mapstructure:"contact"`
	MessageID      string `mapstructure:"messageid"`
	DefaultFrom    string `mapstructure:"default_from"`
	PrimaryOnion   string `mapstructure:"primary_onion"`
	FallbackServer string `mapstructure:"fallback_server"`
	TorProxy       string `mapstructure:"tor_proxy"`
	AlwaysUseTor   bool   `mapstructure:"always_use_tor"`
}

type ThresholdsConfig struct {
	MaxBytes      int `mapstructure:"max_bytes"`
	MaxCrossposts int `mapstructure:"max_crossposts"`
	HoursPast     int `mapstructure:"hours_past"`
	HoursFuture   int `mapstructure:"hours_future"`
	SocketTimeout int `mapstructure:"socket_timeout"`
}

type LoggingConfig struct {
	Level   string `mapstructure:"level"`
	Format  string `mapstructure:"format"`
	DateFmt string `mapstructure:"datefmt"`
	Retain  int    `mapstructure:"retain"`
}

// Global configuration
var config Config

// Initialize logging
func initLogging() {
    // Reindirizza il log a stdout
    log.SetOutput(os.Stdout)
    log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
    log.Println("Logging inizializzato a stdout")
}

// Normalizza il formato dell'email per assicurare compatibilità NNTP
func normalizeEmailFormat(message string) string {
	// Assicurati che ci sia una linea vuota tra gli header e il corpo
	// Questo è fondamentale per il formato NNTP
	headerBodySeparator := "\r\n\r\n"
	if !strings.Contains(message, headerBodySeparator) {
		// Cerca il punto dove terminano gli header (prima riga vuota)
		parts := strings.SplitN(message, "\n\n", 2)
		if len(parts) == 2 {
			// Ricostruisci con \r\n corretto
			message = strings.ReplaceAll(parts[0], "\n", "\r\n") + 
				      "\r\n\r\n" + 
				      strings.ReplaceAll(parts[1], "\n", "\r\n")
			log.Printf("Normalizzato formato email con separatore header-body corretto")
		}
	}
	
	// Assicurati che tutte le righe terminino con \r\n (formato NNTP standard)
	message = strings.ReplaceAll(message, "\r\n", "\n")  // Prima normalizza a \n
	message = strings.ReplaceAll(message, "\n", "\r\n")  // Poi converte tutti i \n in \r\n
	
	// Verifica che non ci siano linee che iniziano con "." e non sono seguite da un altro "."
	// (Nel protocollo NNTP, un "." da solo indica la fine del messaggio)
	lines := strings.Split(message, "\r\n")
	for i, line := range lines {
		if line == "." {
			lines[i] = ".."
			log.Printf("Trovata linea singolo punto, sostituita con '..'")
		} else if strings.HasPrefix(line, ".") && line != ".." {
			lines[i] = "." + line
			log.Printf("Trovata linea che inizia con '.', raddoppiato: %s", lines[i])
		}
	}
	
	return strings.Join(lines, "\r\n")
}

// Parse recipient similar to the Python version
func parseRecipient(user string) (string, string, bool) {
	// Extract domain part if present
	if idx := strings.Index(user, "@"); idx != -1 {
		user = user[:idx]
	}

	// Regular expression to match mail2news format
	re := regexp.MustCompile(`(mail2news|mail2news_nospam)-([0-9]{8})-(.*)`)
	matches := re.FindStringSubmatch(user)
	
	if matches == nil {
		log.Println("Badly formatted recipient. Rejecting message.")
		os.Exit(0)
	}

	recipient := matches[1]
	timestamp := matches[2]
	newsgroups := matches[3]
	
	// Replace = separator with commas
	newsgroups = strings.ReplaceAll(newsgroups, "=", ",")
	
	// Check for nospam directive
	nospam := false
	if recipient == "mail2news_nospam" {
		log.Println("Message includes a nospam directive. Will munge headers accordingly.")
		nospam = true
	}
	
	return timestamp, newsgroups, nospam
}

// Validate timestamp
func validateStamp(stamp string) bool {
	// Parse the stamp into a time.Time
	layout := "20060102"
	parsedTime, err := time.Parse(layout, stamp)
	if err != nil {
		log.Printf("Malformed date element: %v. Rejecting message.", err)
		os.Exit(0)
	}

	// Get current time and calculate boundaries
	now := time.Now().UTC()
	beforeTime := now.Add(-time.Duration(config.Thresholds.HoursPast) * time.Hour)
	afterTime := now.Add(time.Duration(config.Thresholds.HoursFuture) * time.Hour)

	// Check if within bounds
	if parsedTime.After(beforeTime) && parsedTime.Before(afterTime) {
		log.Printf("Timestamp (%s) is valid and within bounds.", stamp)
		return true
	}

	log.Printf("Timestamp (%s) is out of bounds. Rejecting message.", stamp)
	os.Exit(0)
	return false
}

// Validate newsgroups
func ngvalidate(newsgroups string) string {
	newsgroups = strings.TrimRight(newsgroups, ",")
	groups := strings.Split(newsgroups, ",")
	
	var goodng []string
	
	modfile := filepath.Join(config.Paths.Lib, "moderated.db")
	// Check if moderation file exists
	if _, err := os.Stat(modfile); err == nil {
		// Implementation would load the moderated groups
		log.Printf("Moderated groups file found at %s", modfile)
	}
	
	// Check each group format
	re := regexp.MustCompile(`[a-z][a-z0-9]+(\.[0-9a-z-+_]+)+$`)
	for _, ng := range groups {
		ng = strings.TrimSpace(ng)
		
		if re.MatchString(ng) {
			// Check for duplicates
			isDuplicate := false
			for _, existingNg := range goodng {
				if existingNg == ng {
					log.Printf("%s is duplicated in Newsgroups header. Dropping one instance of it.", ng)
					isDuplicate = true
					break
				}
			}
			
			if !isDuplicate {
				// Here would check for moderated groups
				// For now, just add to good newsgroups
				goodng = append(goodng, ng)
			}
		} else {
			log.Printf("%s is not a validated newsgroup, ignoring.", ng)
		}
	}
	
	// No valid newsgroups
	if len(goodng) < 1 {
		log.Println("Message has no valid newsgroups. Rejecting it.")
		os.Exit(0)
	}
	
	// Check crosspost limit
	if len(goodng) > config.Thresholds.MaxCrossposts {
		log.Printf("Message contains %d newsgroups, exceeding crosspost limit of %d. Rejecting.",
			len(goodng), config.Thresholds.MaxCrossposts)
		os.Exit(0)
	}
	
	header := strings.Join(goodng, ",")
	log.Printf("Validated Newsgroups header is: %s", header)
	return header
}

// Generate message ID
func messageID(rightPart string) string {
	// Override the domain with our fixed privacy-enhanced domain
	// Use m2n.tcpreset.nospam instead of the configuration value
	fixedDomain := "tcpreset-nospam"

	// Similar to Python implementation
	now := time.Now().UTC().Format("20060102150405")
	leftPart := now + "." + generateRandomString(12)
	return "<" + leftPart + "@" + fixedDomain + ">"
}

// Generate random string for message ID
func generateRandomString(length int) string {
	// Implementation to generate random string
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// Check blacklists
func blacklistCheck(badFile string, text string) string {
	filename := filepath.Join(config.Paths.Etc, badFile)
	badList := file2list(filename)
	
	if len(badList) > 0 {
		pattern := strings.Join(badList, "|")
		re, err := regexp.Compile(pattern)
		if err != nil {
			log.Printf("Error compiling regex from %s: %v", badFile, err)
			return ""
		}
		
		if match := re.FindString(text); match != "" {
			return match
		}
	}
	
	return ""
}

// Convert file to list
func file2list(filename string) []string {
	var items []string
	
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return items
	}
	
	file, err := os.Open(filename)
	if err != nil {
		return items
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if idx := strings.Index(line, "#"); idx != -1 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line != "" {
			items = append(items, line)
		}
	}
	
	return items
}

// Parse message
func msgParse(message string) (string, string) {
	// Visualizza i primi caratteri del messaggio ricevuto per debug
	firstChars := min(200, len(message))
	log.Printf("Prime %d caratteri del messaggio ricevuto: %s", firstChars, message[:firstChars])
	
	// Rimuovi TUTTE le righe "From " in stile Unix mailbox
	lines := strings.Split(message, "\n")
	var cleanedLines []string
	fromLinesRemoved := 0
	
	for _, line := range lines {
		// Cerca righe "From " che non contengono ":" (caratteristica delle righe mailbox)
		if strings.HasPrefix(line, "From ") && !strings.Contains(line, ":") {
			log.Printf("Rimozione della riga 'From ': %s", line)
			fromLinesRemoved++
			continue // Salta questa riga
		}
		cleanedLines = append(cleanedLines, line)
	}
	
	if fromLinesRemoved > 0 {
		log.Printf("Rimosse %d righe 'From ' dallo stile mailbox", fromLinesRemoved)
		message = strings.Join(cleanedLines, "\n")
		log.Printf("Messaggio dopo rimozione 'From ' - primi %d caratteri: %s", 
			min(100, len(message)), message[:min(100, len(message))])
	} else {
		log.Printf("Nessuna riga 'From ' trovata da rimuovere")
	}
	
	// Skipping history file write due to permission issues
	log.Printf("Skipping history file write due to permission issues")
	
	// Prima di analizzare l'email, assicuriamoci che non abbia altre anomalie di formato
	message = normalizeEmailFormat(message)
	
	// Parse the email
	msg, err := mail.ReadMessage(strings.NewReader(message))
	if err != nil {
		log.Fatalf("Error parsing message: %v", err)
	}
	
	// Process Message-ID
	messageId := msg.Header.Get("Message-ID")
	if messageId == "" {
		// Chiama la funzione messageID passando il parametro della configurazione
		messageId = messageID(config.NNTP.MessageID)
		msg.Header["Message-ID"] = []string{messageId}
		log.Printf("Processing message with no Message-ID. Assigned: %s", messageId)
	} else {
		log.Printf("Processing message: %s", messageId)
	}
	
	// Process Date header
	if msg.Header.Get("Date") == "" {
		log.Println("Message has no Date header. Inserting current timestamp.")
		msg.Header["Date"] = []string{time.Now().Format(time.RFC1123Z)}
	}
	
	// Process From header
	fromHeader := msg.Header.Get("From")
	if fromHeader != "" {
		if match := blacklistCheck("bad_from", fromHeader); match != "" {
			log.Printf("From header matches '%s'. Rejecting.", match)
			os.Exit(1)
		}
	} else {
		log.Println("Message has no From header. Inserting a null one.")
		msg.Header["From"] = []string{config.NNTP.DefaultFrom}
	}
	
	// IMPORTANTE: il codice Python originale NON modifica l'intestazione References
	// Quindi NON facciamo alcuna manipolazione qui, lasciandola inalterata
	
	// Check for poison headers
	poisonFile := filepath.Join(config.Paths.Etc, "headers_poison")
	poisonHeaders := file2list(poisonFile)
	for _, header := range poisonHeaders {
		if msg.Header.Get(header) != "" {
			log.Printf("Message contains a blacklisted %s header. Rejecting it.", header)
			os.Exit(0)
		}
	}
	
	// Get recipient info
	var recipient string
	if to := msg.Header.Get("X-Original-To"); to != "" {
		recipient = to
	} else if to := msg.Header.Get("To"); to != "" {
		recipient = to
	} else {
		recipient = "mail2news@m2n.mixmin.net"
		log.Printf("Could not find recipient info. Guessing %s.", recipient)
	}
	
	if !strings.HasPrefix(recipient, "mail2news") {
		log.Printf("Recipient %s is not us.", recipient)
		os.Exit(2)
	}
	
	// Process newsgroups
	nospam := false
	var dest string
	
	if ng := msg.Header.Get("Newsgroups"); ng != "" {
		dest = ng
		delete(msg.Header, "Newsgroups")
		log.Printf("Message has a Newsgroups header of %s", dest)
		
		if strings.HasPrefix(recipient, "mail2news_nospam") {
			nospam = true
			log.Println("Message includes a nospam directive. Will munge From headers accordingly.")
		}
	} else {
		log.Println("No Newsgroups header, trying to parse recipient information")
		var stamp string
		stamp, dest, nospam = parseRecipient(recipient)
		
		if !validateStamp(stamp) {
			log.Println("No Newsgroups header or valid recipient. Rejecting message.")
			os.Exit(0)
		}
	}
	
	// Validate newsgroups
	validatedGroups := ngvalidate(dest)
	msg.Header["Newsgroups"] = []string{validatedGroups}
	
	// Check for blacklisted newsgroups
	if match := blacklistCheck("bad_groups", validatedGroups); match != "" {
		log.Printf("Newsgroups header matches '%s'. Rejecting.", match)
		os.Exit(1)
	}
	
	// Handle nospam mode
	if nospam {
		// Implementation of fromparse function needed here
		name, addy := fromParse(msg.Header.Get("From"))
		if addy != "" {
			delete(msg.Header, "Author-Supplied-Address")
			delete(msg.Header, "From")
			msg.Header["Author-Supplied-Address"] = []string{addy}
			msg.Header["From"] = []string{name + "<Use-Author-Supplied-Address-Header@[127.1]>"}
		}
	}
	
	// Process Subject header
	if subj := msg.Header.Get("Subject"); subj != "" {
		log.Printf("Subject: %s", subj)
	} else {
		log.Println("Message has no Subject header. Inserting a null one.")
		msg.Header["Subject"] = []string{"None"}
	}
	
	// Check for Path header
	if path := msg.Header.Get("Path"); path != "" {
		log.Printf("Message has a preloaded path header of %s", path)
	}
	
	// Strip headers
	stripFile := filepath.Join(config.Paths.Etc, "headers_strip")
	stripHeaders := file2list(stripFile)
	for _, header := range stripHeaders {
		delete(msg.Header, header)
	}
	
	// Add gateway headers
	msg.Header["Path"] = []string{config.NNTP.Path}
	
	// Add Organization header
	msg.Header["Organization"] = []string{"Tcpreset M2N Gateway"}
	
	// Aggiungi Injection-Info come nel codice Python originale
	msg.Header["Injection-Info"] = []string{
		config.NNTP.InjectionHost + "; mail-complaints-to=" + config.NNTP.Contact,
	}
	
	// IMPORTANTE: a differenza delle versioni precedenti, non proviamo
	// a riordinare le intestazioni. Il codice Python originale non lo fa.
	
	// Usa direttamente il metodo as_string() come nel Python
	txtMsg := ""
	// Costruisci le intestazioni
	for k, vv := range msg.Header {
		for _, v := range vv {
			txtMsg += k + ": " + v + "\r\n"
		}
	}
	
	// Riga vuota tra headers e body
	txtMsg += "\r\n"
	
	// Aggiungi il corpo del messaggio
	body, err := ioutil.ReadAll(msg.Body)
	if err != nil {
		log.Fatalf("Error reading message body: %v", err)
	}
	
	// Assicurarsi che ci sia un corpo, anche minimo
	if len(body) == 0 {
		log.Println("Warning: Empty message body. Adding placeholder text.")
		body = []byte("This message had no content.")
	}
	
	bodyStr := string(body)
	// Normalizza le terminazioni di riga nel corpo
	bodyStr = strings.ReplaceAll(bodyStr, "\r\n", "\n")
	bodyStr = strings.ReplaceAll(bodyStr, "\n", "\r\n")
	
	// Gestisci linee che iniziano con "."
	bodyLines := strings.Split(bodyStr, "\r\n")
	for i, line := range bodyLines {
		if line == "." {
			bodyLines[i] = ".."
		} else if strings.HasPrefix(line, ".") {
			bodyLines[i] = "." + line
		}
	}
	bodyStr = strings.Join(bodyLines, "\r\n")
	
	txtMsg += bodyStr
	
	size := len(txtMsg)
	if size > config.Thresholds.MaxBytes {
		log.Printf("Message exceeds %d size limit. Rejecting.", config.Thresholds.MaxBytes)
		os.Exit(1)
	}
	log.Printf("Message is %d bytes", size)

	// Debug: stampa l'inizio dell'articolo preparato
	startLen := min(500, len(txtMsg))
	log.Printf("Articolo preparato per l'invio (primi %d caratteri):\n%s", startLen, txtMsg[:startLen])
	
	return messageId, txtMsg
}

// min function for Go versions < 1.21
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Parse From header
func fromParse(fromHdr string) (string, string) {
	var name, addy string
	matched := false
	
	// Pattern 1: "Name <user@example.com>"
	re1 := regexp.MustCompile(`([^<>]*)<([^<>\s]+@[^<>\s]+)>$`)
	if matches := re1.FindStringSubmatch(fromHdr); matches != nil {
		name = matches[1]
		addy = matches[2]
		matched = true
	}
	
	// Pattern 2: "user@example.com (Name)"
	re2 := regexp.MustCompile(`([^<>\s]+@[^<>\s]+)\s+\(([^\(\)]*)\)$`)
	if !matched {
		if matches := re2.FindStringSubmatch(fromHdr); matches != nil {
			name = matches[2]
			addy = matches[1]
			matched = true
		}
	}
	
	// Pattern 3: "user@example.com"
	re3 := regexp.MustCompile(`([^<>\s]+@[^<>\s]+)$`)
	if !matched {
		if matches := re3.FindStringSubmatch(fromHdr); matches != nil {
			name = ""
			addy = matches[1]
		}
	}
	
	if addy != "" {
		addy = strings.ReplaceAll(addy, ".", "<DOT>")
		addy = strings.ReplaceAll(addy, "@", "<AT>")
	}
	
	return name, addy
}

// Send news
func newsSend(mid string, content string) {
	// Implementation for NNTP sending
	// Using Tor for all connections
	hostFile := filepath.Join(config.Paths.Etc, "nntphosts")
	hosts := file2list(hostFile)
	
	// Default Tor proxy address if not specified in config
	torProxyAddr := "127.0.0.1:9050"
	if config.NNTP.TorProxy != "" {
		torProxyAddr = config.NNTP.TorProxy
	}
	
	// Create a SOCKS5 dialer for Tor
	torDialer, err := proxy.SOCKS5("tcp", torProxyAddr, nil, proxy.Direct)
	if err != nil {
		log.Printf("Error creating Tor dialer: %v", err)
		return
	}
	
	// Try primary onion server first if configured
	primarySuccess := false
	if config.NNTP.PrimaryOnion != "" {
		primaryServer := config.NNTP.PrimaryOnion
		if !strings.Contains(primaryServer, ":") {
			primaryServer += ":119" // Default NNTP port
		}
		
		log.Printf("Attempting delivery to primary onion service: %s", primaryServer)
		err := deliverViaTor(torDialer, primaryServer, mid, content)
		
		if err == nil {
			log.Printf("✓ %s successfully delivered to primary onion service", mid)
			primarySuccess = true
		} else {
			log.Printf("✗ Delivery to primary onion service failed: %v", err)
		}
	}
	
	// If primary fails, try fallback server
	if !primarySuccess && config.NNTP.FallbackServer != "" {
		fallbackServer := config.NNTP.FallbackServer
		if !strings.Contains(fallbackServer, ":") {
			fallbackServer += ":119" // Default NNTP port
		}
		
		log.Printf("Attempting delivery to fallback server: %s", fallbackServer)
		err := deliverViaTor(torDialer, fallbackServer, mid, content)
		
		if err == nil {
			log.Printf("✓ %s successfully delivered to fallback server", mid)
		} else {
			log.Printf("✗ Delivery to fallback server failed: %v", err)
		}
	}
	
	// If configured, also try additional hosts from nntphosts file
	if len(hosts) > 0 {
		log.Printf("Attempting delivery to %d additional NNTP servers", len(hosts))
		
		for _, host := range hosts {
			// Skip if it's one of our already-tried hosts
			if host == config.NNTP.PrimaryOnion || host == config.NNTP.FallbackServer {
				continue
			}
			
			// Ensure host has port
			if !strings.Contains(host, ":") {
				host += ":119" // Default NNTP port
			}
			
			log.Printf("Attempting delivery to %s", host)
			err := deliverViaTor(torDialer, host, mid, content)
			
			if err == nil {
				log.Printf("✓ %s successfully delivered to %s", mid, host)
			} else {
				log.Printf("✗ Delivery to %s failed: %v", host, err)
			}
		}
	}

	log.Printf("Programma mail2news terminato correttamente")
}

// Deliver message via Tor to a specific NNTP server
// IMPORTANTE: Come nel codice Python, tentiamo solo IHAVE senza fallback a POST
func deliverViaTor(torDialer proxy.Dialer, host string, messageID string, content string) error {
	// Create a dialer with timeout
	timeoutDialer := &net.Dialer{
		Timeout: time.Duration(config.Thresholds.SocketTimeout) * time.Second,
	}
	
	// Use Tor for .onion addresses or if always_use_tor is enabled
	var conn net.Conn
	var err error
	
	if strings.Contains(host, ".onion") || config.NNTP.AlwaysUseTor {
		// Connect through Tor
		log.Printf("Connecting to %s via Tor proxy", host)
		conn, err = torDialer.Dial("tcp", host)
	} else {
		// Direct connection
		log.Printf("Connecting directly to %s", host)
		conn, err = timeoutDialer.Dial("tcp", host)
	}
	
	if err != nil {
		return fmt.Errorf("connection error: %v", err)
	}
	defer conn.Close()
	
	// Set deadline for the entire conversation
	deadline := time.Now().Add(time.Duration(config.Thresholds.SocketTimeout) * time.Second)
	conn.SetDeadline(deadline)
	
	// Set up buffered reader/writer
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	
	// Read initial greeting
	resp, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("error reading greeting: %v", err)
	}
	if !strings.HasPrefix(resp, "200 ") && !strings.HasPrefix(resp, "201 ") {
		return fmt.Errorf("unexpected greeting: %s", resp)
	}
	
	respTrimmed := strings.TrimSpace(resp)
	log.Printf("Connected to %s, greeting: %s", host, respTrimmed)
	
	// Usa solo IHAVE come nel codice Python originale
	log.Printf("Sending IHAVE command with Message-ID: %s", messageID)
	ihaveCmd := fmt.Sprintf("IHAVE %s\r\n", messageID)
	_, err = writer.WriteString(ihaveCmd)
	if err != nil {
		return fmt.Errorf("error sending IHAVE: %v", err)
	}
	err = writer.Flush()
	if err != nil {
		return fmt.Errorf("error flushing IHAVE: %v", err)
	}
	
	// Read response to IHAVE
	resp, err = reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("error reading IHAVE response: %v", err)
	}
	
	respTrimmed = strings.TrimSpace(resp)
	log.Printf("IHAVE response from %s: %s", host, respTrimmed)
	
	// Check if server accepted IHAVE
	if !strings.HasPrefix(resp, "335 ") {
		// Se non accetta IHAVE, semplicemente falliamo (come nel Python)
		return fmt.Errorf("IHAVE not accepted: %s", respTrimmed)
	}
	
	// Send article content
	log.Printf("Server %s accepted IHAVE, sending content", host)
	_, err = writer.WriteString(content + "\r\n.\r\n")
	if err != nil {
		return fmt.Errorf("error sending article: %v", err)
	}
	err = writer.Flush()
	if err != nil {
		return fmt.Errorf("error flushing article: %v", err)
	}
	
	// Read final response
	resp, err = reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("error reading final response: %v", err)
	}
	
	respTrimmed = strings.TrimSpace(resp)
	log.Printf("Final response from %s: %s", host, respTrimmed)
	
	// Check if article was accepted
	if !strings.HasPrefix(resp, "235 ") {
		return fmt.Errorf("article rejected: %s", respTrimmed)
	}
	
	// Send QUIT
// Check if article was accepted
	if !strings.HasPrefix(resp, "235 ") {
		return fmt.Errorf("article rejected: %s", respTrimmed)
	}
	
	// Send QUIT
	writer.WriteString("QUIT\r\n")
	writer.Flush()
	
	return nil
}

func main() {
	// Log iniziale per segnalare l'avvio
	log.Printf("CANARY: Mail2News versione 7 con compatibilità Python è in esecuzione!")
	
	// Seed random number generator
	rand.Seed(time.Now().UnixNano())
	
	// Initialize config
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("/etc/mail2news")
	viper.AddConfigPath("$HOME/.mail2news")
	viper.AddConfigPath(".")
	
	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Fatal error config file: %s", err)
	}
	
	if err := viper.Unmarshal(&config); err != nil {
		log.Fatalf("Unable to decode config: %s", err)
	}
	
	// Initialize logging
	initLogging()
	
	fmt.Println("Type message here. Finish with Ctrl-D.")
	
	// Read message from stdin
	message, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		log.Fatalf("Error reading from stdin: %v", err)
	}
	
	// Parse and process message
	mid, payload := msgParse(string(message))
	
	// Send to news servers
	newsSend(mid, payload)
	
	log.Printf("Programma mail2news terminato correttamente")
}
