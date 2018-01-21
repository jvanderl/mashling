package eftl

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/url"

	"github.com/TIBCOSoftware/flogo-lib/core/activity"
	"github.com/TIBCOSoftware/flogo-lib/logger"
	"github.com/jvanderl/tib-eftl"
	opentracing "github.com/opentracing/opentracing-go"
	ctx "golang.org/x/net/context"
)

const (
	ivTracing = "tracing"
	ovTracing = "tracing"
)

// log is the default package logger
var log = logger.GetLogger("activity-jvanderl-eftl")

// MyActivity is a stub for your Activity implementation
type MyActivity struct {
	metadata *activity.Metadata
}

// NewActivity creates a new AppActivity
func NewActivity(metadata *activity.Metadata) activity.Activity {
	return &MyActivity{metadata: metadata}
}

// Metadata implements activity.Activity.Metadata
func (a *MyActivity) Metadata() *activity.Metadata {
	return a.metadata
}

// Eval implements activity.Activity.Eval - Sends a message to TIBCO eFTL
func (a *MyActivity) Eval(context activity.Context) (done bool, err error) {
	var span opentracing.Span
	if tracing := context.GetInput(ivTracing); tracing != nil {
		span = opentracing.SpanFromContext(tracing.(ctx.Context))
	}

	if span != nil {
		span = opentracing.StartSpan(
			context.TaskName(),
			opentracing.ChildOf(span.Context()))
		context.SetOutput(ovTracing, opentracing.ContextWithSpan(ctx.Background(), span))
		defer span.Finish()
	}

	setTag := func(key string, value interface{}) {
		if span != nil {
			span.SetTag(key, value)
		}
	}

	logError := func(format string, a ...interface{}) {
		str := fmt.Sprintf(format, a...)
		setTag("error", str)
		log.Error(str)
	}

	// Get the activity data from the context
	wsHost := context.GetInput("server").(string)
	wsClientID := context.GetInput("clientid").(string)
	wsChannel := context.GetInput("channel").(string)
	setTag("channel", wsChannel)
	wsDestination := context.GetInput("destination").(string)
	setTag("destination", wsDestination)
	wsSubject := context.GetInput("subject").(string)
	setTag("subject", wsSubject)
	wsMessage := context.GetInput("message").(string)
	wsUser := context.GetInput("user").(string)
	wsPassword := context.GetInput("password").(string)
	wsSecure := context.GetInput("secure").(bool)
	wsCert := context.GetInput("certificate").(string)

	wsURL := url.URL{}
	if wsSecure {
		wsURL = url.URL{Scheme: "wss", Host: wsHost, Path: wsChannel}
	} else {
		wsURL = url.URL{Scheme: "ws", Host: wsHost, Path: wsChannel}
	}
	wsConn := wsURL.String()
	setTag("url", wsConn)

	var tlsConfig *tls.Config

	if wsCert != "" {
		// TLS configuration uses CA certificate from a PEM file to
		// authenticate the server certificate when using wss:// for
		// a secure connection
		caCert, err := base64.StdEncoding.DecodeString(wsCert)
		if err != nil {
			log.Errorf("unable to decode certificate: %s", err)
			return false, err
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		tlsConfig = &tls.Config{
			RootCAs: caCertPool,
		}
	} else {
		// TLS configuration accepts all server certificates
		// when using wss:// for a secure connection
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	// channel for receiving connection errors
	errChan := make(chan error, 1)

	// set connection options
	opts := &eftl.Options{
		ClientID:  wsClientID,
		Username:  wsUser,
		Password:  wsPassword,
		TLSConfig: tlsConfig,
	}

	// connect to the server
	conn, err := eftl.Connect(wsConn, opts, errChan)
	if err != nil {
		context.SetOutput("result", "ERR_CONNECT_HOST")
		logError("Error Connectining to host: %s", err)
		return false, err
	}

	// close the connection when done
	defer conn.Disconnect()

	// channel for receiving publish completions
	compChan := make(chan *eftl.Completion, 1000)

	// publish the message
	conn.PublishAsync(eftl.Message{
		"_dest": wsDestination,
		"_cid":  wsClientID,
		"_subj": wsSubject,
		"text":  wsMessage,
	}, compChan)

	for {
		select {
		case comp := <-compChan:
			if comp.Error != nil {
				logError("Error while sending message to wsHost: [%s]", comp.Error)
				context.SetOutput("result", "ERR_SEND_MESSAGE")
				return false, comp.Error
			}
			log.Debugf("published message: %s", comp.Message)
			context.SetOutput("result", "OK")
			return true, nil
		case err := <-errChan:
			logError("connection error: %s", err)
			context.SetOutput("result", "ERR_CONNECT_HOST")
			return false, err
		}
	}

}
