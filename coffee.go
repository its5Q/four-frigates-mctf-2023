package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Type and constant definitions

type State int

const (
	Idle State = iota
	Brewing
	Pouring
	DrinkReady
)

var acceptedSchemes = []string{
	"koffie", "q%C3%A6hv%C3%A6", "%D9%82%D9%87%D9%88%D8%A9", "akeita",
	"koffee", "kahva", "kafe", "caf%C3%E8", "%E5%92%96%E5%95%A1", "kava",
	"k%C3%A1va", "kaffe", "coffee", "kafo", "kohv", "kahvi", "%4Baffee",
	"%CE%BA%CE%B1%CF%86%CE%AD", "%E0%A4%95%E0%A5%8C%E0%A4%AB%E0%A5%80",
	"%E3%82%B3%E3%83%BC%E3%83%92%E3%83%BC", "%EC%BB%A4%ED%94%BC",
	"%D0%BA%D0%BE%D1%84%D0%B5", "%E0%B8%81%E0%B8%B2%E0%B9%81%E0%B8%9F",
}

type Addition struct {
	kind     string
	name     string
	quality  float64
	quantity float64
}

type Drink struct {
	name      string
	additions []Addition
	quantity  float64
}

type CoffeeMachine struct {
	potId             string
	state             State
	brewTimestamp     time.Time
	acceptedAdditions []Addition
	drink             Drink
}

type ReceivedRequest struct {
	conn    net.Conn
	httpReq *Request
}

var asciiCoffee []byte
var flag string

var brewTime = 5 * time.Second
var maxPourTime = 20 * time.Second
var additionFlowRate = 15.
var milkRequired = 90.
var delta = 7.5

// Global state variables
var coffeeMachines map[string]CoffeeMachine
var drinksServed = 0

func main() {
	port := 1337
	// port, err := strconv.ParseInt(os.Getenv("PORT"), 10, 0)
	// if err != nil {
	// 	log.Fatalln("No port specified in PORT environment variable")
	// }

	// potsPath := os.Getenv("POTS")
	// if potsPath == "" {
	// 	log.Fatalln("No path to pot ids specified in POTS environment variable")
	// }

	flag = os.Getenv("FLAG")
	if flag == "" {
		log.Fatalln("No flag specified in FLAG environment variable")
	}

	// Reading coffee ASCII art
	var err error
	asciiCoffee, err = os.ReadFile("coffee.txt")
	if err != nil {
		log.Fatalf("Error reading coffee ASCII file: %s", err)
	}

	// Reading pot ids and creating coffee machines
	potFile, err := os.Open("pots.txt")
	if err != nil {
		log.Fatalf("Error opening pot file: %s", err)
	}
	defer potFile.Close()

	coffeeMachines = make(map[string]CoffeeMachine)
	scanner := bufio.NewScanner(potFile)
	for scanner.Scan() {
		potId := scanner.Text()
		coffeeMachines[potId] = CoffeeMachine{
			potId: potId,
			state: Idle,
			acceptedAdditions: []Addition{
				{kind: "milk", name: "Cream", quality: 0.4},
				{kind: "milk", name: "Half-and-half", quality: 0.25},
				{kind: "milk", name: "Whole-milk", quality: 0.3},
				{kind: "milk", name: "Part-Skim", quality: 0.8},
				{kind: "milk", name: "Skim", quality: 0},
				{kind: "milk", name: "Non-Dairy", quality: 0.5},

				{kind: "syrup", name: "Vanilla", quality: 0.9},
				{kind: "syrup", name: "Almond", quality: 0.6},
				{kind: "syrup", name: "Raspberry", quality: 0.75},
				{kind: "syrup", name: "Non-Chocolate", quality: 0.5},

				{kind: "soda", name: "Coca-Cola", quality: 1},
			},
			drink: Drink{},
		}

		log.Printf("Created coffee machine with pot-id %s", potId)
	}

	// Serving TCP clients with goroutines
	l, err := net.Listen("tcp4", ":"+strconv.Itoa(int(port)))
	if err != nil {
		log.Fatalf("Error starting listener: %s", err)
	}
	defer l.Close()

	log.Printf("Listener started on port %d", port)

	reqChan := make(chan ReceivedRequest)

	// Accepting connections, receiving requests and sending them to a channel
	go func(reqChan chan<- ReceivedRequest) {
		for {
			c, err := l.Accept()
			if err != nil {
				log.Printf("Error accepting client: %s", err)
				continue
			}

			go func(reqChan chan<- ReceivedRequest) {
				c.SetDeadline(time.Now().Add(15 * time.Second))
				// defer c.Close() - we should close in a channel
				log.Printf("Serving %s\n", c.RemoteAddr().String())
				req, err := ReadRequest(bufio.NewReader(c))
				if err != nil {
					log.Printf("Error reading request: %s", err)
					resp := http.Response{
						ProtoMajor:    1,
						ProtoMinor:    0,
						ContentLength: -1,
						Close:         true,
						Header:        http.Header{},
					}
					resp.Header.Set("Server", "Goffee/1.0")

					resp.StatusCode = 400
					resp.Status = "400 Bad Request"
					resp.Body = io.NopCloser(strings.NewReader(""))

					respBuf := new(bytes.Buffer)
					resp.Write(respBuf)
					respBytes := bytes.Replace(respBuf.Bytes(), []byte("HTTP/1.0"), []byte("HTCPCP/1.0"), 1)
					c.Write(respBytes)
					c.Close()
					return
				}

				reqChan <- ReceivedRequest{conn: c, httpReq: req}
			}(reqChan)

		}
	}(reqChan)

	// Processing incoming requests from a channel
	for request := range reqChan {
		resp := processRequest(request.httpReq)

		log.Printf("%s \"%s %s %s\" %d", request.conn.RemoteAddr().String(), request.httpReq.Method, request.httpReq.URL.Path, request.httpReq.Proto, resp.StatusCode)
		if os.Getenv("DEBUG") == "1" {
			log.Printf("%+v", request.httpReq)
		}

		respBuf := new(bytes.Buffer)
		resp.Write(respBuf)
		respBytes := bytes.Replace(respBuf.Bytes(), []byte("HTTP/1.0"), []byte("HTCPCP/1.0"), 1)
		request.conn.Write(respBytes)
		request.conn.Close()
	}

}

func formatAdditions(additions []Addition) string {
	var additionStrs []string
	for _, addition := range additions {
		additionStrs = append(additionStrs, addition.kind+"-type/"+addition.name+";q="+strconv.FormatFloat(addition.quality, 'f', -1, 64))
	}
	return strings.Join(additionStrs, ",")
}

func parseAdditions(additionsStr string) (additions []Addition, err error) {
	defer func() {
		if err2 := recover(); err2 != nil {
			log.Println("error parsing additions: ", err2, string(debug.Stack()))
			additions = make([]Addition, 0)
			err = err2.(error)
		}
	}()

	for _, additionStr := range strings.Split(strings.ReplaceAll(additionsStr, " ", ""), ",") {
		addition := Addition{}
		addition.kind = strings.Split(strings.Split(additionStr, "/")[0], "-")[0]
		addition.name = strings.Split(strings.Split(additionStr, "/")[1], ";")[0]
		additions = append(additions, addition)
	}

	return additions, nil
}

func parseQueryAdditions(query url.Values) (addition Addition, err error) {
	defer func() {
		if err2 := recover(); err2 != nil {
			log.Println("error parsing query additions: ", err2, string(debug.Stack()))
			addition = Addition{}
			err = err2.(error)
		}
	}()

	for k, v := range query {
		addition.kind = strings.Split(k, "-")[0]
		addition.name = v[0]
	}

	return addition, nil
}

func Contains(haystack []Addition, needle Addition) bool {
	for _, addition := range haystack {
		if addition.kind == needle.kind && addition.name == needle.name {
			return true
		}
	}
	return false
}

func getBrewingStatus(potId string) (CoffeeMachine, error) {
	now := time.Now()
	coffeeMachine := coffeeMachines[potId]
	if coffeeMachine.drink.name == "" {
		coffeeMachine.drink.name = "Coffee"
		if timePassed := now.Sub(coffeeMachine.brewTimestamp); timePassed < brewTime {
			coffeeMachine.drink.quantity = (30. / brewTime.Seconds()) * timePassed.Seconds()
		} else if len(coffeeMachine.drink.additions) == 0 {
			coffeeMachine.state = DrinkReady
			return coffeeMachine, nil
		} else if timePassed >= brewTime && timePassed < maxPourTime {
			coffeeMachine.state = Pouring
			coffeeMachine.drink.additions[0].quantity = (timePassed.Seconds() - brewTime.Seconds()) * additionFlowRate
			coffeeMachine.drink.quantity = 30 + coffeeMachine.drink.additions[0].quantity

		} else {
			coffeeMachine.state = Idle
			coffeeMachine.drink = Drink{}
			return coffeeMachine, errors.New("Drink overflow")
		}
	}

	return coffeeMachine, nil
}

func isSolved(coffeeMachine CoffeeMachine) bool {
	return coffeeMachine.drink.name == "Coffee" && len(coffeeMachine.drink.additions) == 1 && ((milkRequired-delta) <= coffeeMachine.drink.additions[0].quantity && coffeeMachine.drink.additions[0].quantity <= (milkRequired+delta)) && coffeeMachine.drink.additions[0].kind == "milk" && coffeeMachine.drink.additions[0].name == "Part-Skim"
}

func processRequest(req *Request) (resp http.Response) {
	resp.ProtoMajor = 1
	resp.ProtoMinor = 0
	resp.ContentLength = -1
	resp.Close = true
	resp.Header = http.Header{}
	resp.Header.Set("Server", "Goffee/1.0")

	defer func() {
		if err := recover(); err != nil {
			log.Println("error handling request: ", err, string(debug.Stack()))
			resp.StatusCode = 500
			resp.Status = "500 Internal Server Error"
			resp.Body = io.NopCloser(strings.NewReader("Unexpected error occured. Please contact the challenge creator."))
		}
	}()

	// Check if valid request
	if req == nil {
		resp.StatusCode = 400
		resp.Status = "400 Bad Request"
		resp.Body = io.NopCloser(strings.NewReader(""))
		return resp
	}

	// Check protocol
	if req.Proto != "HTCPCP/1.0" {
		resp.StatusCode = 400
		resp.Status = "400 Bad Request"
		resp.Body = io.NopCloser(strings.NewReader("Invalid protocol"))
		return resp
	}

	// Check method
	if !slices.Contains([]string{"GET", "POST", "BREW", "PROPFIND", "WHEN"}, req.Method) {
		resp.StatusCode = 405
		resp.Status = "405 Method not allowed"
		return resp
	}

	// Check pot-id
	var potId string
	if strings.HasPrefix(req.URL.Path, "/pot-") {
		var potIdEnd int

		if potIdEnd = strings.Index(req.URL.Path[5:], "/"); potIdEnd == -1 {
			potIdEnd = len(req.URL.Path)
		} else {
			potIdEnd += 5
		}
		potId = req.URL.Path[5:potIdEnd]

		if _, ok := coffeeMachines[potId]; !ok {
			resp.StatusCode = 403
			resp.Status = "403 Forbidden"
			resp.Body = io.NopCloser(strings.NewReader("Unknown pot specified"))
			return resp
		}
	} else if req.URL.Path == "/" && req.Method == "GET" {
		resp.StatusCode = 200
		resp.Status = "200 OK"
		resp.Body = io.NopCloser(strings.NewReader(fmt.Sprintf("<h2>M*CTF coffee machine powered by Goffee/1.0. Served %d drinks so far.</h2>", drinksServed)))
		return resp
	} else {
		resp.StatusCode = 400
		resp.Status = "400 Bad Request"
		resp.Body = io.NopCloser(strings.NewReader("No pot specified"))
		return resp
	}

	// Check "scheme"
	if !slices.Contains(acceptedSchemes, req.Header.Get("X-Scheme")) {
		resp.StatusCode = 400
		resp.Status = "400 Bad Request"
		resp.Body = io.NopCloser(strings.NewReader("Invalid X-Scheme header"))
		return resp
	}

	if strings.HasSuffix(req.URL.Path, "/reset") {
		coffeeMachine := coffeeMachines[potId]
		coffeeMachine.state = Idle
		coffeeMachine.drink = Drink{}
		coffeeMachine.brewTimestamp = time.Time{}
		coffeeMachines[potId] = coffeeMachine
		resp.StatusCode = 200
		resp.Status = "200 OK"
		resp.Body = io.NopCloser(strings.NewReader("Coffee machine has been reset."))
		return resp
	}

	// Return 404 on any path other than the pot
	if strings.Count(req.URL.Path, "/") > 1 {
		resp.StatusCode = 404
		resp.Status = "404 Not Found"
		resp.Body = io.NopCloser(strings.NewReader(""))
		return resp
	}

	if req.Method == "GET" {
		if coffeeMachines[potId].state == Idle {
			resp.StatusCode = 200
			resp.Status = "200 OK"
			resp.Header.Add("Accept-Additions", formatAdditions(coffeeMachines[potId].acceptedAdditions))
			resp.Body = io.NopCloser(strings.NewReader("Pot is idle and waiting for requests."))
			return resp
		} else if coffeeMachines[potId].state == Brewing {
			coffeeMachine, err := getBrewingStatus(potId)
			if err != nil {
				coffeeMachines[potId] = coffeeMachine
				resp.StatusCode = 500
				resp.Status = "500 Drink Overflow"
				resp.Body = io.NopCloser(strings.NewReader(""))
				return resp
			}

			if coffeeMachine.state == DrinkReady {
				resp.StatusCode = 200
				resp.Status = "200 OK"
				if isSolved(coffeeMachine) {
					resp.Body = io.NopCloser(bytes.NewReader(append([]byte("                "+flag+"\n"), asciiCoffee...)))
				} else {
					resp.Body = io.NopCloser(bytes.NewReader(asciiCoffee))
				}
				coffeeMachine.state = Idle
				coffeeMachine.drink = Drink{}
				coffeeMachines[potId] = coffeeMachine
				return resp
			}

			resp.StatusCode = 503
			resp.Status = "503 Service Temporarily Unavailable"
			resp.Body = io.NopCloser(strings.NewReader("The pot is busy."))
			return resp
		} else if coffeeMachines[potId].state == DrinkReady {
			resp.StatusCode = 200
			resp.Status = "200 OK"
			if isSolved(coffeeMachines[potId]) {
				resp.Body = io.NopCloser(bytes.NewReader(append([]byte("                "+flag+"\n"), asciiCoffee...)))
			} else {
				resp.Body = io.NopCloser(bytes.NewReader(asciiCoffee))
			}
			coffeeMachine := coffeeMachines[potId]
			coffeeMachine.state = Idle
			coffeeMachine.drink = Drink{}
			coffeeMachines[potId] = coffeeMachine
			return resp
		}
	} else if req.Method == "POST" || req.Method == "BREW" {
		if req.Header.Get("Content-Type") != "message/coffeepot" {
			resp.StatusCode = 415
			resp.Status = "415 Unsupported Media Type"
			resp.Body = io.NopCloser(strings.NewReader("Unknown or no Content-Type specified."))
			return resp
		}

		if coffeeMachines[potId].state != Idle {
			resp.StatusCode = 503
			resp.Status = "503 Service Temporarily Unavailable"
			resp.Body = io.NopCloser(strings.NewReader("The pot is busy."))
			return resp
		}

		// Check required body
		// Hack required to parse it

		t := req.Header.Get("Content-Type")
		t2 := req.Method
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.ParseForm()
		req.Header.Set("Content-Type", t)
		req.Method = t2

		reqBody, _ := io.ReadAll(req.Body)
		log.Println(string(reqBody))
		if !(bytes.Equal(reqBody, []byte("coffee-message-body=start")) || bytes.Equal(reqBody, []byte("coffee-message-body=stop"))) {
			resp.StatusCode = 400
			resp.Status = "400 Bad Request"
			resp.Body = io.NopCloser(strings.NewReader("Invalid request body."))
			return resp
		}

		if bytes.Equal(reqBody, []byte("coffee-message-body=stop")) {
			resp.StatusCode = 501
			resp.Status = "501 Not Implemented"
			resp.Body = io.NopCloser(strings.NewReader("Brew interruption is unsupported by this coffee machine."))
			return resp
		}

		// Parsing additions
		reqQuery := req.URL.Query()
		reqAcceptAdditions := req.Header.Get("Accept-Additions")
		var selectedAddition Addition
		var err error
		if len(reqQuery) > 1 {
			resp.StatusCode = 501
			resp.Status = "501 Not Implemented"
			resp.Body = io.NopCloser(strings.NewReader("Sorry, this coffee machine doesn't support multiple additions at a time."))
			return resp
		} else if len(reqQuery) == 1 {
			selectedAddition, err = parseQueryAdditions(reqQuery)
			if err != nil {
				resp.StatusCode = 400
				resp.Status = "400 Bad Request"
				resp.Body = io.NopCloser(strings.NewReader("Malformed additions query parameter."))
				return resp
			}
		} else if reqAcceptAdditions != "" {
			headerAdditions, err := parseAdditions(reqAcceptAdditions)
			if err != nil {
				resp.StatusCode = 400
				resp.Status = "400 Bad Request"
				resp.Body = io.NopCloser(strings.NewReader("Malformed Accept-Additions header."))
				return resp
			}

			if len(headerAdditions) > 1 {
				resp.StatusCode = 501
				resp.Status = "501 Not Implemented"
				resp.Body = io.NopCloser(strings.NewReader("Sorry, this coffee machine doesn't support multiple additions at a time."))
				return resp
			} else if len(headerAdditions) == 1 {
				selectedAddition = headerAdditions[0]
			}
		}

		// Checking if the addition is supported
		if selectedAddition.kind != "" && selectedAddition.name != "" && !Contains(coffeeMachines[potId].acceptedAdditions, selectedAddition) {
			resp.StatusCode = 406
			resp.Status = "406 Not Acceptable"
			resp.Body = io.NopCloser(strings.NewReader("Specified addition is not supported."))
			return resp
		}

		if selectedAddition.name == "Coca-Cola" {
			resp.StatusCode = 451
			resp.Status = "451 Unavailable For Legal Reasons"
			resp.Body = io.NopCloser(strings.NewReader(""))
			return resp
		}

		// Starting to brew
		coffeeMachine := coffeeMachines[potId]
		coffeeMachine.state = Brewing
		coffeeMachine.brewTimestamp = time.Now()
		if selectedAddition.kind != "" && selectedAddition.name != "" {
			coffeeMachine.drink.additions = append(coffeeMachine.drink.additions, selectedAddition)
		}

		coffeeMachines[potId] = coffeeMachine

		resp.StatusCode = 202
		resp.Status = "202 Accepted"
		resp.Body = io.NopCloser(strings.NewReader("Your brewing request will be processed shortly."))
		drinksServed += 1

		return resp
	} else if req.Method == "PROPFIND" {
		var coffeeMachine CoffeeMachine
		var err error
		if coffeeMachines[potId].state == Brewing {
			coffeeMachine, err = getBrewingStatus(potId)
			if err != nil {
				coffeeMachines[potId] = coffeeMachine
				resp.StatusCode = 500
				resp.Status = "500 Drink Overflow"
				resp.Body = io.NopCloser(strings.NewReader(""))
				return resp
			}
		} else {
			coffeeMachine = coffeeMachines[potId]
		}

		resp.StatusCode = 200
		resp.Status = "200 OK"
		var statusStr string
		switch coffeeMachine.state {
		case Idle:
			statusStr = "idle"
		case Brewing:
			statusStr = "brewing"
		case Pouring:
			statusStr = "pouring"
		case DrinkReady:
			statusStr = "drink_ready"
		}

		resp.Header.Set("Content-Type", "application/json")

		if coffeeMachine.state == Idle {
			resp.Body = io.NopCloser(
				strings.NewReader(
					fmt.Sprintf(
						"{\"status\":\"%s\",\"drink\":{}}",
						statusStr,
					),
				),
			)
		} else {
			resp.Body = io.NopCloser(
				strings.NewReader(
					fmt.Sprintf(
						"{\"status\":\"%s\",\"drink\":{\"name\":\"%s\",\"quantity\":%f,\"additions\":{\"kind\":\"%s\",\"name\":\"%s\",\"quantity\":%f}}}",
						statusStr, coffeeMachine.drink.name, coffeeMachine.drink.quantity,
						coffeeMachine.drink.additions[0].kind, coffeeMachine.drink.additions[0].name,
						coffeeMachine.drink.additions[0].quantity,
					),
				),
			)
		}

		return resp
	} else if req.Method == "WHEN" {
		var coffeeMachine CoffeeMachine
		var err error
		if coffeeMachines[potId].state == Brewing {
			coffeeMachine, err = getBrewingStatus(potId)
			if err != nil {
				coffeeMachines[potId] = coffeeMachine
				resp.StatusCode = 500
				resp.Status = "500 Drink Overflow"
				resp.Body = io.NopCloser(strings.NewReader(""))
				return resp
			}
		} else {
			resp.StatusCode = 406
			resp.Status = "406 Not Acceptable"
			resp.Body = io.NopCloser(strings.NewReader("Not pouring any additions right now."))
			return resp
		}

		if coffeeMachine.state == Pouring {
			coffeeMachine.state = DrinkReady
			coffeeMachines[potId] = coffeeMachine
			resp.StatusCode = 201
			resp.Status = "201 Created"
			resp.Header.Set("Location", "/pot-"+potId)
			resp.Body = io.NopCloser(strings.NewReader(""))
			return resp
		} else {
			resp.StatusCode = 406
			resp.Status = "406 Not Acceptable"
			resp.Body = io.NopCloser(strings.NewReader("We haven't started pouring additions yet."))
			return resp
		}
	}

	resp.StatusCode = 500
	resp.Status = "500 Internal Server Error"
	resp.Body = io.NopCloser(strings.NewReader("Unexpected error occured. Please contact the challenge creator."))
	return resp
}
