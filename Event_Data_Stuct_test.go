package main

import (
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func Test_Event_Data(t *testing.T) {
	layout := "Jan _2 15:04:05"
	time, _ := time.Parse(layout, "Oct 27 14:48:15")

	f := false
	// var nilbool bool
	TestCase := []struct {
		TestDescription string
		TestLog         string
		ExpectedEvent   Event
		ExpectedErr     bool
	}{
		{

			TestDescription: "Inital Test with first log from Journal",
			TestLog:         "Oct 27 14:48:15 NoahHamner sshd-session[11258]: Failed password for developer from 172.27.0.1 port 53040 ssh2",
			ExpectedErr:     false,
			ExpectedEvent: Event{
				TargetInfo: TargetInfo{
					TargetUsername: "developer",
					TargetService:  "sshd-session",
				},
				SourceInfo: SourceInfo{
					SourcePort: 53040,
					IpAddress:  netip.MustParseAddr("172.27.0.1"),
				},
				TimeStamp:         time,
				AuthOutcome:       &f,
				LogMessage:        "Oct 27 14:48:15 NoahHamner sshd-session[11258]: Failed password for developer from 172.27.0.1 port 53040 ssh2",
				LogSourceHostName: "NoahHamner",
			},
		},
		{

			TestDescription: "Checking if a malformed SSH log causes a panick",
			TestLog:         "Oct 27 14:48:15 NoahHamner sshd-session[11258]: Failed password for developer from NOT_AN_IP port 53040 ssh2",
			ExpectedErr:     true,
			ExpectedEvent:   Event{},
		}, {
			TestDescription: "Checking if a truncated SSH log causes a panick",
			TestLog:         "Oct 27 14:48:15 NoahHamner sshd-session[11258]: Failed password",
			ExpectedErr:     true,
			ExpectedEvent:   Event{},
		},
	}

	for _, tC := range TestCase {
		ActualEvent, err := Failed_Password_Parser(tC.TestLog)
		if (err != nil) != tC.ExpectedErr {
			t.Errorf("The test %v did not output the expected error", tC.TestDescription)
		}
		if !(reflect.DeepEqual(tC.ExpectedEvent, ActualEvent)) {
			t.Errorf("Expected: %+v\nActual: %+v", tC.ExpectedEvent, ActualEvent) // fmt.Println(tC.ExpectedEvent)

		}
	}
}

func Test_Choosing_Integraion(t *testing.T) {
	layout := "Jan _2 15:04:05"
	time, _ := time.Parse(layout, "Oct 27 14:48:15")

	f := false
	// var nilbool bool
	TestCase := []struct {
		TestDescription string
		TestLog         string
		ExpectedEvent   Event
		ExpectedErr     bool
	}{
		{

			TestDescription: "Inital Test with first log from Journal",
			TestLog:         "Oct 27 14:48:15 NoahHamner sshd-session[11258]: Failed password for developer from 172.27.0.1 port 53040 ssh2",
			ExpectedErr:     false,
			ExpectedEvent: Event{
				TargetInfo: TargetInfo{
					TargetUsername: "developer",
					TargetService:  "sshd-session",
				},
				SourceInfo: SourceInfo{
					SourcePort: 53040,
					IpAddress:  netip.MustParseAddr("172.27.0.1"),
				},
				TimeStamp:         time,
				AuthOutcome:       &f,
				LogMessage:        "Oct 27 14:48:15 NoahHamner sshd-session[11258]: Failed password for developer from 172.27.0.1 port 53040 ssh2",
				LogSourceHostName: "NoahHamner",
			},
		}, {

			TestDescription: "Checking if a malformed SSH log causes a panick",
			TestLog:         "Oct 27 14:48:15 NoahHamner sshd-session[11258]: Failed password for developer from NOT_AN_IP port 53040 ssh2",
			ExpectedErr:     true,
			ExpectedEvent:   Event{},
		}, {
			TestDescription: "Checking if a truncated SSH log causes a panick",
			TestLog:         "Oct 27 14:48:15 NoahHamner sshd-session[11258]: Failed password",
			ExpectedErr:     true,
			ExpectedEvent:   Event{},
		}, {
			TestDescription: "Checking if the identifier can correctly remove a log",
			TestLog:         "Oct 27 14:48:15 NoahHamner sshd-session[11258]: Accepted password for developer from 172.27.0.1 port 53040 ssh2",
			ExpectedErr:     true,
			ExpectedEvent:   Event{},
		},
		{
			TestDescription: "Checking if the identifier can correctly parse a failed ssh and failed username",
			TestLog:         "Oct 27 14:48:15 NoahHamner sshd-session[11258]: Failed password for invalid user admin from 172.27.0.1 port 53040 ssh2",
			ExpectedErr:     false,
			ExpectedEvent: Event{
				TargetInfo: TargetInfo{
					TargetUsername:      "admin",
					TargetUserNameExist: &f,
					TargetService:       "sshd-session",
				},
				SourceInfo: SourceInfo{
					SourcePort: 53040,
					IpAddress:  netip.MustParseAddr("172.27.0.1"),
				},
				TimeStamp:         time,
				AuthOutcome:       &f,
				LogMessage:        "Oct 27 14:48:15 NoahHamner sshd-session[11258]: Failed password for invalid user admin from 172.27.0.1 port 53040 ssh2",
				LogSourceHostName: "NoahHamner",
			},
		},
	}
	for _, tC := range TestCase {
		ActualEvent, err := log_type_identifier(tC.TestLog)
		if (err != nil) != tC.ExpectedErr {
			t.Errorf("The test %v did not output the expected error", tC.TestDescription)
		}
		if !(reflect.DeepEqual(tC.ExpectedEvent, ActualEvent)) {
			t.Errorf("Expected: %+v\nActual: %+v", tC.ExpectedEvent, ActualEvent) // fmt.Println(tC.ExpectedEvent)

		}
	}
}

// Oct 27 14:48:15 NoahHamner sshd-session[11258]:
// Failed password for developer from 172.27.0.1 port 53040 ssh2
