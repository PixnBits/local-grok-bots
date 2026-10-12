package main

import "testing"

func TestRefuseRoot(t *testing.T) {
	if err := refuseRoot(0); err == nil {
		t.Fatal("root was accepted")
	}
	if err := refuseRoot(1000); err != nil {
		t.Fatal(err)
	}
}
