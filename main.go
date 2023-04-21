package main

import (
	"fmt"
	"log"
	"regexp"
	"sync"
	"time"
  
  "gitlab.com/honour/abuseipdb"
	"github.com/hpcloud/tail"
)

type BruteForce struct {
	mu         sync.Mutex
	IP         string
	Usernames  map[string]bool
	Attempts   int
	LastReport time.Time
}

func (b *BruteForce) AddUsername(username string) {
	b.mu.Lock()
	b.Usernames[username] = true
	b.Attempts++
	b.mu.Unlock()
}

func (b *BruteForce) Reset() {
	b.mu.Lock()
	b.Usernames = make(map[string]bool)
	b.Attempts = 0
	b.mu.Unlock()
}

func (b *BruteForce) String() string {
	b.mu.Lock()
	uniqueUsernames := len(b.Usernames)
	b.mu.Unlock()

	return fmt.Sprintf("[Bruteforce] %s - Usernames: %d - Attempts: %d", b.IP, uniqueUsernames, b.Attempts)
}

func reportAbuseIPDB(ip string, categories []abuseipdb.Category, comment abuseipdb.ReportOption) error {
	client := abuseipdb.NewClient("api key")

	reportResponse, err := client.Report(ip, categories, comment)

	if err != nil {
		return err
	}

	fmt.Println(reportResponse)

	return nil

}

func main() {
	filename := "/var/log/auth.log"
	t, err := tail.TailFile(filename, tail.Config{Follow: true})
	if err != nil {
		log.Fatal(err)
	}

	// regex for invalid ssh pass
	logRegexp := regexp.MustCompile(`Failed password for (invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+)`)

	bruteForces := make(map[string]*BruteForce)
	var mu sync.Mutex

	checkInterval := 60 * time.Second
	reportInterval := 24 * time.Hour
	ticker := time.NewTicker(checkInterval)

	go func() {
		for _ = range ticker.C {
			mu.Lock()
			for _, bf := range bruteForces {
				if bf.Attempts > 3 && time.Since(bf.LastReport) > reportInterval {
					fmt.Println(bf.String())
          err := reportAbuseIPDB(bf.IP, []abuseipdb.Category{abuseipdb.CategoryBruteForce, abuseipdb.CategorySSH}, abuseipdb.Comment(bf.String()))
          if err != nil {
            log.Println(err)
          }

					bf.LastReport = time.Now()
					bf.Reset()
				} else if bf.Attempts > 3 {
					bf.Reset()
				}
			}
			mu.Unlock()
		}
	}()

	for line := range t.Lines {
		matches := logRegexp.FindStringSubmatch(line.Text)
		if matches == nil {
			continue
		}

		ip := matches[3]
		username := matches[2]

		mu.Lock()
		bf, ok := bruteForces[ip]
		if !ok {
			bf = &BruteForce{
				IP:         ip,
				Usernames:  make(map[string]bool),
				LastReport: time.Now().Add(-reportInterval),
			}
			bruteForces[ip] = bf
		}
		bf.AddUsername(username)
		mu.Unlock()
	}
}
