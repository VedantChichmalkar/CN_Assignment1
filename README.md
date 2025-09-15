# CS331: Computer Networks - Assignment 1: DNS Resolver

This repository contains the source code and documentation for the DNS Resolver project, as part of the **CS331: Computer Networks** course.

---

## Team Members
- **Member 1:** Vedant Chichmalkar (22110282)  
- **Member 2:** Rutvi Shah (22110227)

---

## Project Overview
This project implements a custom DNS resolution system consisting of a client and a server.

- The **client** parses a given PCAP file, extracts DNS query packets, adds a custom header (*timestamp + sequence ID*), and sends them to the server.  
- The **server** receives these packets and, based on rules defined in `rules.json`, performs **time-based load balancing**.  
- It uses the timestamp and sequence ID from the custom header to select an IP address from a predefined pool and sends it back to the client.

---

## Directory Structure
```bash
├── client.py # The client application
├── server.py # The server application
├── rules.json # Predefined rules for DNS resolution (NEW)
├── main.py # Main execution script
└── README.md # This file
```

# How to Run

## 1. Choose your PCAP file
As per the assignment guidelines, select the correct `X.pcap` file.  
Place it in the project's root directory.

---

## 2. Start the Server
Open a terminal and run:

```bash
python main.py server
```
The server will load rules.json and wait for packets on localhost:5300.

## 3. Run the Client
Open a second terminal and run the client, passing the name of your PCAP file:

```bash
python main.py client --pcap_file your_pcap_file.pcap
```
Replace your_pcap_file.pcap with the actual name of your PCAP file.

## 3. View the Output
Server terminal will show:

  -  The custom header
  -  The domain name
  -  The IP it resolved (based on the time-based rules)

Client terminal will log:
  - The transaction details


