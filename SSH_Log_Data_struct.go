// This file is made to contain a normalized data struct for a SSH connection attempt
package main

import (
	"net/netip"
	"time"
)

type TargetInfo struct {
	// Username of account being targeted
	TargetUsername string
	// Does the username exist
	TargetUserNameExist *bool
	// Name of service being targeted (ssh ftp ect)
	TargetService string
}
type SourceInfo struct {
	// Port on client side of connection
	SourcePort int
	// IP adress of the remote host
	IpAddress netip.Addr
}

type Event struct {
	TargetInfo
	SourceInfo

	// Time of the event
	TimeStamp time.Time
	// Whether authentication was sucessful, denied, or N/A
	AuthOutcome *bool
	// Original String containing full log
	LogMessage string
	// What host the log came from
	LogSourceHostName string
}
