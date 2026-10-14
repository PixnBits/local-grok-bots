package model

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestToolParseErrorClassifiesXML(t *testing.T) {
	got, ok := AsToolCallParseError("XML syntax error on line 3: unexpected end element </parameter>")
	if !ok || got.Error() != "ollama: XML syntax error on line 3: unexpected end element </parameter>" {
		t.Fatalf("xml error %#v %v", got, ok)
	}
	if _, ok := AsToolCallParseError("qwen tool call parsing failed"); !ok {
		t.Fatal("parser failure was not classified")
	}
	if _, ok := AsToolCallParseError("model not found"); ok {
		t.Fatal("model not found was classified as a parse error")
	}
}

func TestChatMapsToolCallParseError(t *testing.T) {
	const xml = "XML syntax error on line 3: unexpected end element </parameter>"
	xmlSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "{\"error\":%q}\n", xml)
	}))
	t.Cleanup(xmlSrv.Close)
	_, err := NewOllama(xmlSrv.URL).Chat(context.Background(), ChatRequest{Model: "m"}, nil)
	var parseErr *ToolCallParseError
	if !errors.As(err, &parseErr) || parseErr.Detail != xml {
		t.Fatalf("got %v", err)
	}
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "{\"error\":\"model not found\"}\n")
	}))
	t.Cleanup(other.Close)
	_, err = NewOllama(other.URL).Chat(context.Background(), ChatRequest{Model: "m"}, nil)
	if err == nil || errors.As(err, &parseErr) || err.Error() != "ollama: model not found" {
		t.Fatalf("got %v", err)
	}
}
