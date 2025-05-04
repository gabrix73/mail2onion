package main

import (
	"fmt"
	"html/template"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/smtp"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// Function to generate random alphanumeric strings
func generateRandomString(length int) string {
	rand.Seed(time.Now().UnixNano())
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[rand.Intn(len(charset))]
	}
	return string(result)
}

// Generate a Message-ID with a random part
func generateMessageID() string {
	timestamp := time.Now().Unix()
	randomPart := generateRandomString(12)
	return fmt.Sprintf("<%d.%s@mail2onion>", timestamp, randomPart)
}

const htmlTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Victor Mail2News Interface</title>
	<style>
		body {
			background-color: white;
			color: black;
			font-family: Arial, sans-serif;
		}
		.container {
			width: 50%;
			margin: auto;
			padding: 20px;
			border: 2px solid red;
			background-color: black;
			color: white;
		}
		button {
			background-color: red;
			color: white;
			padding: 10px;
			border: none;
			cursor: pointer;
		}
		button:hover {
			background-color: darkred;
		}
		footer {
			margin-top: 20px;
			text-align: center;
			background-color: red;
			color: black;
			padding: 10px;
		}
		footer a {
			color: black;
			text-decoration: none;
		}
		footer a:hover {
			text-decoration: underline;
		}
		.info {
			background-color: #333;
			padding: 10px;
			margin-bottom: 10px;
			border-left: 3px solid red;
		}
		.help-text {
			font-size: 0.8em;
			color: #aaa;
			margin-top: 5px;
		}
	</style>
</head>
<body>
	<div class="container">
		<h2>Send Emails to Mail2News</h2>
		
		<div class="info">
			This interface sends messages to mail2news@xilb7y4kj6u6qfo45o3yk2kilfv54ffukzei3puonuqlncy7cn2afwyd.onion gateway for news://peannyjkqwqfynd24p6dszvtchkq7hfkwymi5by5y332wmosy5dwfaqd.onion<br><br>
			We do not collect or store IP addresses or any other personal information.
		</div>
		
		<form method="POST" action="/send">
			<label for="from">From:</label><br>
			<input type="text" id="from" name="from" placeholder="User Name<email@address>" required><br><br>

			<label for="newsgroup">Newsgroup:</label><br>
			<input type="text" id="newsgroup" name="newsgroup" required><br><br>

			<label for="subject">Subject:</label><br>
			<input type="text" id="subject" name="subject" required><br><br>

			<label for="message">Message:</label><br>
			<textarea id="message" name="message" rows="10" cols="50" required></textarea><br><br>

			<label for="references">References:</label><br>
			<input type="text" id="references" name="references" placeholder="<message-id@example.com>,<another-id@domain.com>"><br>
			<div class="help-text">For replies, enter one or more Message-IDs separated by commas</div><br>

			<label for="smtp_choice">SMTP Server:</label><br>
			<select id="smtp_choice" name="smtp_choice">
				<option value="auto" selected>Auto (try all servers)</option>
				<option value="xilb7y4kj6u6qfo45o3yk2kilfv54ffukzei3puonuqlncy7cn2afwyd.onion:25">xilb7y4kj6u6qfo45o3yk2kilfv54ffukzei3puonuqlncy7cn2afwyd.onion:25</option>
				<option value="dkudsc3rn7r4m2gdvje6vmcnmglmt2m6whc3oazd65oyi7mvfbgfnzqd.onion:25">dkudsc3rn7r4m2gdvje6vmcnmglmt2m6whc3oazd65oyi7mvfbgfnzqd.onion:25</option>
                <option value="custom">Other (custom)</option>
			</select>
			<br><br>
			<div id="custom_smtp_div" style="display:none;">
				<label for="smtp_custom">Custom SMTP:</label><br>
				<input type="text" id="smtp_custom" name="smtp_custom" placeholder="smtp.example.com:25"><br>
				<small>Additional possible addresses at SEC3: <a href="https://www.sec3.net/misc/mail-relays.html" target="_blank">this link</a>.</small>
				<br><br>
			</div>

			<button type="submit">Send</button>
		</form>
	</div>
	<footer>
<div style="text-align: center;">
  <div>
    <a href="https://github.com/gabrix73/mail2dizum.git" target="_blank">
      <svg role="img" viewBox="0 0 24 24" width="24" height="24" xmlns="http://www.w3.org/2000/svg">
        <title>GitHub</title>
        <path fill="currentColor" d="M12 0C5.373 0 0 5.373 0 12c0 5.303 3.438 9.8 8.205 11.387.6.111.82-.261.82-.58 0-.285-.011-1.04-.017-2.04-3.338.724-4.042-1.612-4.042-1.612-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.73.083-.73 1.205.085 1.838 1.237 1.838 1.237 1.07 1.834 2.807 1.304 3.492.997.108-.775.419-1.305.762-1.605-2.665-.3-5.466-1.333-5.466-5.93 0-1.312.47-2.383 1.236-3.222-.124-.303-.536-1.523.117-3.176 0 0 1.008-.322 3.301 1.23a11.51 11.51 0 013.003-.404 11.48 11.48 0 013.003.404c2.291-1.552 3.297-1.23 3.297-1.23.655 1.653.243 2.873.12 3.176.77.84 1.235 1.91 1.235 3.222 0 4.61-2.805 5.625-5.475 5.922.43.37.823 1.103.823 2.222 0 1.606-.015 2.898-.015 3.293 0 .321.216.697.825.579C20.565 21.796 24 17.303 24 12c0-6.627-5.373-12-12-12z"/>
      </svg>
      GitHub
    </a>
  </div>
  <div>
    <a href="https://yamn.virebent.art" target="_blank">
      Victor Hostile Communicazion Center
    </a>
  </div>
  <div>
    <a href="https://xilb7y4kj6u6qfo45o3yk2kilfv54ffukzei3puonuqlncy7cn2afwyd.onion" target="_blank">
      Powered by xilb7y4kj6u6qfo45o3yk2kilfv54ffukzei3puonuqlncy7cn2afwyd.onion
    </a>
  </div>
</div>	
	</footer>
	<script>
		document.getElementById("smtp_choice").addEventListener("change", function() {
			if (this.value === "custom") {
				document.getElementById("custom_smtp_div").style.display = "block";
			} else {
				document.getElementById("custom_smtp_div").style.display = "none";
			}
		});
		
		// Automatically add "Re:" prefix to subject when References has content
		document.getElementById("references").addEventListener("input", function() {
			var subject = document.getElementById("subject");
			
			if (this.value.trim() && !subject.value.startsWith("Re:")) {
				subject.value = "Re: " + subject.value;
			} else if (!this.value.trim() && subject.value.startsWith("Re: ")) {
				subject.value = subject.value.substring(4);
			}
		});
	</script>
</body>
</html>
`

// tryConnectToSMTP attempts to connect to a SMTP server via Tor with extended timeout
func tryConnectToSMTP(smtpServer string) (net.Conn, error) {
	log.Printf("Attempting to connect to SMTP server %s via SOCKS5...", smtpServer)
	
	// Configure the SOCKS5 proxy for Tor with custom timeout dialer
	torDialer, err := proxy.SOCKS5("tcp4", "127.0.0.1:9050", nil, proxy.Direct)
	if err != nil {
		log.Printf("SOCKS5 configuration error: %v", err)
		return nil, fmt.Errorf("SOCKS5 configuration error: %v", err)
	}
	
	// Attempt connection with a longer timeout (3 minutes)
	var conn net.Conn
	connChan := make(chan net.Conn, 1)
	errChan := make(chan error, 1)
	
	// Try connection in a goroutine
	go func() {
		c, e := torDialer.Dial("tcp4", smtpServer)
		if e != nil {
			errChan <- e
			return
		}
		connChan <- c
	}()
	
	// Wait for connection with timeout
	select {
	case conn = <-connChan:
		log.Println("SOCKS5 connection established successfully.")
	case err = <-errChan:
		log.Printf("SOCKS5 connection error to %s: %v", smtpServer, err)
		return nil, fmt.Errorf("SOCKS5 connection error to %s: %v", smtpServer, err)
	case <-time.After(3 * time.Minute):
		return nil, fmt.Errorf("connection timeout after 3 minutes")
	}
	
	return conn, nil
}

// sendMailThroughTorWithServer sends the email via Tor using the specified SMTP server.
// Returns the Message-ID of the sent message and any error that occurred.
func sendMailThroughTorWithServer(smtpServer, fromHeader, newsgroup, subject, message, references string) (string, error) {
	// Extract email address from fromHeader (which is in format "Name <email@example.com>")
	re := regexp.MustCompile(`<([^>]+)>`)
	matches := re.FindStringSubmatch(fromHeader)
	var fromEmail string
	if len(matches) > 1 {
		fromEmail = matches[1]
	} else {
		// Fallback if regex doesn't match
		fromEmail = fromHeader
	}

	// Use a fixed recipient for all messages
	recipient := "mail2news@xilb7y4kj6u6qfo45o3yk2kilfv54ffukzei3puonuqlncy7cn2afwyd.onion"

	// Adjust subject for replies if needed - based on References field
	if references != "" && !strings.HasPrefix(subject, "Re:") {
		subject = "Re: " + subject
	}

	// Generate a new Message-ID for this message with random part
	thisMessageId := generateMessageID()
	
	// Format all headers
	headers := make([]string, 0)
	headers = append(headers, fmt.Sprintf("From: %s", fromHeader))
	headers = append(headers, fmt.Sprintf("To: %s", recipient))
	headers = append(headers, fmt.Sprintf("Newsgroups: %s", newsgroup))
	headers = append(headers, fmt.Sprintf("Subject: %s", subject))
	headers = append(headers, fmt.Sprintf("Message-ID: %s", thisMessageId))
	headers = append(headers, "X-No-Archive: Yes")
	headers = append(headers, "Content-Type: text/plain; charset=utf-8")
	headers = append(headers, "Content-Transfer-Encoding: 8bit")
	headers = append(headers, "MIME-Version: 1.0")
	
	// Add threading headers if References is provided
	if references != "" {
		// For proper threading in most NNTP servers
		headers = append(headers, fmt.Sprintf("References: %s", references))
		
		// In-Reply-To should only contain the last Message-ID in the References chain
		// Extract the last Message-ID from the References list
		refParts := strings.Split(references, ",")
		if len(refParts) > 0 {
			// Get the last reference and trim any whitespace
			lastRef := strings.TrimSpace(refParts[len(refParts)-1])
			headers = append(headers, fmt.Sprintf("In-Reply-To: %s", lastRef))
		}
	}
	
	// Add date header (required by RFC)
	now := time.Now()
	headers = append(headers, fmt.Sprintf("Date: %s", now.Format(time.RFC1123Z)))
	
	// Combine headers and message body
	msg := strings.Join(headers, "\r\n") + "\r\n\r\n" + message

	// Log the complete message for debugging
	log.Println("Complete message headers:")
	for _, header := range headers {
		log.Println("  " + header)
	}
	
	// Connect to the SMTP server via the proxy
	conn, err := tryConnectToSMTP(smtpServer)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	// Create the SMTP client
	host := strings.Split(smtpServer, ":")[0]
	log.Println("Creating SMTP connection without TLS...")
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		log.Printf("SMTP client creation error: %v", err)
		return "", fmt.Errorf("SMTP client creation error: %v", err)
	}
	log.Println("SMTP client created successfully.")
	defer client.Close()

	// Send MAIL FROM command
	log.Printf("Sending MAIL FROM command with: %s", fromEmail)
	if err := client.Mail(fromEmail); err != nil {
		log.Printf("MAIL FROM command error: %v", err)
		return "", fmt.Errorf("MAIL FROM command error: %v", err)
	}

	// Send RCPT TO command
	log.Printf("Sending RCPT TO command with: %s", recipient)
	if err := client.Rcpt(recipient); err != nil {
		log.Printf("RCPT TO command error: %v", err)
		return "", fmt.Errorf("RCPT TO command error: %v", err)
	}

	// Write the message body
	log.Println("Writing message body...")
	wc, err := client.Data()
	if err != nil {
		log.Printf("DATA command error: %v", err)
		return "", fmt.Errorf("DATA command error: %v", err)
	}
	_, err = wc.Write([]byte(msg))
	if err != nil {
		log.Printf("Message body writing error: %v", err)
		return "", fmt.Errorf("Message body writing error: %v", err)
	}
	wc.Close()

	// Close the SMTP connection
	log.Println("Closing SMTP connection...")
	if err := client.Quit(); err != nil {
		log.Printf("QUIT command error: %v", err)
		return "", fmt.Errorf("QUIT command error: %v", err)
	}

	log.Printf("Message sent successfully through %s", smtpServer)
	return thisMessageId, nil
}

// sendMailThroughTor tries multiple SMTP servers if needed
func sendMailThroughTor(serverChoice, fromHeader, newsgroup, subject, message, references, customServer string) (string, error) {
	var servers []string
	
	// Determine which servers to try
	if serverChoice == "auto" {
		// Try both onion servers in sequence
		servers = []string{
			"xilb7y4kj6u6qfo45o3yk2kilfv54ffukzei3puonuqlncy7cn2afwyd.onion:25",
			"dkudsc3rn7r4m2gdvje6vmcnmglmt2m6whc3oazd65oyi7mvfbgfnzqd.onion:25",
		}
	} else if serverChoice == "custom" {
		// Only try the custom server
		servers = []string{customServer}
	} else {
		// Try the specific server chosen
		servers = []string{serverChoice}
	}
	
	// Try each server in sequence until one works
	var lastError error
	for _, server := range servers {
		log.Printf("Trying SMTP server: %s", server)
		messageID, err := sendMailThroughTorWithServer(server, fromHeader, newsgroup, subject, message, references)
		if err == nil {
			// Success! Return the message ID
			return messageID, nil
		}
		
		// Store the error and try the next server
		lastError = err
		log.Printf("Server %s failed: %v. Trying next server...", server, err)
	}
	
	// If we get here, all servers failed
	return "", fmt.Errorf("all SMTP servers failed. Last error: %v", lastError)
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		tmpl, err := template.New("webpage").Parse(htmlTemplate)
		if err != nil {
			log.Printf("Error parsing HTML template: %s\n", err.Error())
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if err := tmpl.Execute(w, nil); err != nil {
			log.Printf("Error executing HTML template: %s\n", err.Error())
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	})

	http.HandleFunc("/send", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Error reading form", http.StatusBadRequest)
			return
		}

		// Read form fields
		fromHeader := r.FormValue("from")
		newsgroup := r.FormValue("newsgroup")
		subject := r.FormValue("subject")
		message := r.FormValue("message")
		references := r.FormValue("references")

		// Select the SMTP server
		smtpChoice := r.FormValue("smtp_choice")
		var customServer string
		if smtpChoice == "custom" {
			customServer = r.FormValue("smtp_custom")
			if customServer == "" {
				http.Error(w, "Invalid SMTP address", http.StatusBadRequest)
				return
			}
		}

		// Validate the From field (format: User Name<email@address>)
		fromPattern := regexp.MustCompile("^[^<>]+<[^<>@]+@[^<>]+>$")
		if !fromPattern.MatchString(fromHeader) {
			http.Error(w, "Invalid From. Required format: User Name<email@address>", http.StatusBadRequest)
			return
		}
		newsgroupPattern := regexp.MustCompile(`^(?:[a-zA-Z0-9._-]+)(?:\s*,\s*[a-zA-Z0-9._-]+){0,2}$`)
		if !newsgroupPattern.MatchString(newsgroup) {
			http.Error(w, "Invalid newsgroup - It must contain up to three groups separated by commas", http.StatusBadRequest)
			return
		}
		if !regexp.MustCompile(`^[^\r\n]+$`).MatchString(subject) {
			http.Error(w, "Invalid subject", http.StatusBadRequest)
			return
		}

		// Validate the message (at least one character allowed, any character)
		if !regexp.MustCompile("(?s)^.+$").MatchString(message) {
			http.Error(w, "Invalid message", http.StatusBadRequest)
			return
		}
		
		// If References is provided, validate its format
		// Allow multiple Message-IDs separated by commas
		if references != "" {
			// Split by commas and check each Message-ID
			refIDs := strings.Split(references, ",")
			for i, refID := range refIDs {
				// Trim whitespace from each ID
				refID = strings.TrimSpace(refID)
				if !regexp.MustCompile(`^<[^>]+>$`).MatchString(refID) {
					http.Error(w, fmt.Sprintf("Invalid Message-ID format in References: %s. Each ID must be in the format: <message-id@example.com>", refID), http.StatusBadRequest)
					return
				}
				// Put the trimmed version back in the array
				refIDs[i] = refID
			}
			// Rejoin with commas and no spaces (standard format)
			references = strings.Join(refIDs, " ")
		}

		// Send the message via Tor with automatic fallback
		messageID, err := sendMailThroughTor(smtpChoice, fromHeader, newsgroup, subject, message, references, customServer)
		if err != nil {
			log.Printf("Error sending message: %s\n", err)
			http.Error(w, fmt.Sprintf("Error sending message: %s", err), http.StatusInternalServerError)
			return
		}

		log.Printf("Message sent successfully with ID: %s", messageID)
		
		// Simplified success page with Message-ID
		successHTML := fmt.Sprintf(`
		<html>
		<head>
			<style>
				body {
					font-family: Arial, sans-serif;
					margin: 30px;
					text-align: center;
				}
				.message-id {
					background-color: #f0f0f0;
					padding: 10px;
					border: 1px solid #ccc;
					border-radius: 5px;
					font-family: monospace;
					margin: 20px 0;
					word-break: break-all;
				}
				.back-link {
					margin-top: 20px;
				}
			</style>
		</head>
		<body>
			<h2>Message sent successfully!</h2>
			<p>Your message has been assigned this Message-ID:</p>
			<div class="message-id">%s</div>
			<div class="back-link"><a href="/">Go back</a></div>
		</body>
		</html>`, messageID)
		
		fmt.Fprintf(w, successHTML)
	})

	log.Println("Server listening on http://localhost:8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
