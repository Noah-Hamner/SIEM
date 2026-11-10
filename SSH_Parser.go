package main

import (
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

func main() {
	Failed_Password_Invalid_Username_Parser("Oct 27 14:48:15 NoahHamner sshd-session[11258]: Failed password for invalid user admin from 172.27.0.1 port 53040 ssh2")
}

func log_type_identifier(log string) (Event, error) {
	log_type := choose_type_log(log)
	var CurrentEvent Event
	var CurrentError error

	if log_type == "Failed Password" {
		CurrentEvent, CurrentError = Failed_Password_Parser(log)
		return CurrentEvent, CurrentError
	}
	if log_type == "Failed Password and Failed User" {
		CurrentEvent, CurrentError = Failed_Password_Invalid_Username_Parser(log)
		return CurrentEvent, CurrentError

	}
	return CurrentEvent, errors.New("Unsupportd type")
}

func choose_type_log(log_message string) string {
	FailedPassword := strings.Contains(log_message, "Failed password")
	InvalidUser := strings.Contains(log_message, "invalid user")

	switch {
	case FailedPassword && InvalidUser:
		return "Failed Password and Failed User"
	case FailedPassword:
		return "Failed Password"
	case InvalidUser:
		return "Invalid User"
	default:
		return "Neither"
	}
}

func Failed_Password_Parser(log_message string) (Event, error) {
	var TargetUserNameExist *bool
	var Time string
	var Hostname string
	var TargetService string
	var CurEvent Event
	log_message_slice := strings.Split(log_message, " ")
	if len(log_message_slice) <= 13 {
		err := errors.New("Slice is not the right length")
		return CurEvent, err
	}
	for i := range 3 {
		Time = Time + " " + log_message_slice[i]
	}
	layout := "Jan _2 15:04:05"
	Time = strings.Trim(Time, " ")
	TimeFormat, err_time := time.Parse(layout, Time)

	if err_time != nil {
		return CurEvent, err_time
	}
	Hostname = log_message_slice[3]

	TargetService = log_message_slice[4]
	TargetServiceSlice := strings.Split(TargetService, "[")
	TargetService = TargetServiceSlice[0]

	TargetUsername := log_message_slice[8]

	SourceIp, err_ip := netip.ParseAddr(log_message_slice[10])

	if err_ip != nil {

		return CurEvent, err_ip
	}

	AuthOutcome := false

	SourcePort, err_source_port := strconv.Atoi(log_message_slice[12])

	if err_source_port != nil {
		return CurEvent, err_source_port
	}

	CurEvent = Event{
		TargetInfo: TargetInfo{
			TargetUsername:      TargetUsername,
			TargetUserNameExist: TargetUserNameExist,
			TargetService:       TargetService,
		},
		SourceInfo: SourceInfo{
			IpAddress:  SourceIp,
			SourcePort: SourcePort,
		},
		TimeStamp:         TimeFormat,
		AuthOutcome:       &AuthOutcome,
		LogMessage:        log_message,
		LogSourceHostName: Hostname,
	}

	return CurEvent, nil
}

func Failed_Password_Invalid_Username_Parser(log_message string) (Event, error) {
	TargetUserNameExist := false
	var Time string
	var Hostname string
	var TargetService string
	var CurEvent Event
	// Oct 27 14:48:15 NoahHamner sshd-session[11258]: Failed password for invalid user admin from 172.27.0.1 port 53040 ssh2
	// Oct 27 14:48:15 NoahHamner sshd-session[11258]: Failed password for developer from 172.27.0.1 port 53040 ssh2

	log_message_slice := strings.Split(log_message, " ")
	if len(log_message_slice) <= 15 {
		err := errors.New("Slice is not the right length")
		return CurEvent, err
	}
	for i := range 3 {
		Time = Time + " " + log_message_slice[i]
	}
	layout := "Jan _2 15:04:05"
	Time = strings.Trim(Time, " ")
	TimeFormat, err_time := time.Parse(layout, Time)

	if err_time != nil {
		return CurEvent, err_time
	}
	Hostname = log_message_slice[3]

	TargetService = log_message_slice[4]
	TargetServiceSlice := strings.Split(TargetService, "[")
	TargetService = TargetServiceSlice[0]

	TargetUsername := log_message_slice[10]

	SourceIp, err_ip := netip.ParseAddr(log_message_slice[12])

	if err_ip != nil {

		return CurEvent, err_ip
	}

	AuthOutcome := false

	SourcePort, err_source_port := strconv.Atoi(log_message_slice[14])

	if err_source_port != nil {
		return CurEvent, err_source_port
	}

	CurEvent = Event{
		TargetInfo: TargetInfo{
			TargetUsername:      TargetUsername,
			TargetUserNameExist: &TargetUserNameExist,
			TargetService:       TargetService,
		},
		SourceInfo: SourceInfo{
			IpAddress:  SourceIp,
			SourcePort: SourcePort,
		},
		TimeStamp:         TimeFormat,
		AuthOutcome:       &AuthOutcome,
		LogMessage:        log_message,
		LogSourceHostName: Hostname,
	}
	return CurEvent, nil

}
