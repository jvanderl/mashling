package eftl

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"reflect"
	"strconv"

	"github.com/TIBCOSoftware/flogo-contrib/action/flow/support"
	"github.com/TIBCOSoftware/flogo-lib/core/action"
	"github.com/TIBCOSoftware/flogo-lib/core/trigger"
	"github.com/TIBCOSoftware/flogo-lib/logger"
	condition "github.com/TIBCOSoftware/mashling/lib/conditions"
	"github.com/TIBCOSoftware/mashling/lib/util"
	"github.com/jvanderl/tib-eftl"
	lightstep "github.com/lightstep/lightstep-tracer-go"
	opentracing "github.com/opentracing/opentracing-go"
	zipkin "github.com/openzipkin/zipkin-go-opentracing"
	"sourcegraph.com/sourcegraph/appdash"
	appdashtracing "sourcegraph.com/sourcegraph/appdash/opentracing"
	//	"strings"
)

const (
	TracerNoOP      = "noop"
	TracerZipKin    = "zipkin"
	TracerAPPDash   = "appdash"
	TracerLightStep = "lightstep"

	settingDestination    = "destination"
	settingUseSubject     = "usesubject"
	settingSubject        = "subject"
	settingTracer         = "tracer"
	settingTracerEndpoint = "tracerEndpoint"
	settingTracerToken    = "tracerToken"
	settingTracerDebug    = "tracerDebug"
	settingTracerSameSpan = "tracerSameSpan"
	settingTracerID128Bit = "tracerID128Bit"
)

var (
	ErrorTracerEndpointRequired = errors.New("tracer endpoint required")
	ErrorInvalidTracer          = errors.New("invalid tracer")
	ErrorTracerTokenRequired    = errors.New("tracer token required")
)

// log is the default package logger
var log = logger.GetLogger("trigger-jvanderl-eftl")

// Span is a tracing span
type Span struct {
	opentracing.Span
}

// Error is for reporting errors
func (s *Span) Error(format string, a ...interface{}) {
	str := fmt.Sprintf(format, a...)
	s.SetTag("error", str)
	log.Error(str)
}

//OptimizedHandler optimized handler
type OptimizedHandler struct {
	defaultActionId string
	dispatches      []*Dispatch
}

// GetActionID gets the action id of the matched handler
func (h *OptimizedHandler) GetActionID(payload string, span Span) string {
	actionId := ""

	for _, dispatch := range h.dispatches {
		expressionStr := dispatch.condition
		//Get condtion and expression type
		conditionOperation, exprType, err := condition.GetConditionOperationAndExpressionType(expressionStr)

		if err != nil || exprType == condition.EXPR_TYPE_NOT_VALID {
			span.Error("not able parse the condition '%v' mentioned for content based handler. skipping the handler.", expressionStr)
			continue
		}

		log.Debugf("Expression type: %v", exprType)
		log.Debugf("conditionOperation.LHS %v", conditionOperation.LHS)
		log.Debugf("conditionOperation.OperatorInfo %v", conditionOperation.OperatorInfo().Names)
		log.Debugf("conditionOperation.RHS %v", conditionOperation.RHS)

		//Resolve expression's LHS based on expression type and
		//evaluate the expression
		if exprType == condition.EXPR_TYPE_CONTENT {
			exprResult, err := condition.EvaluateCondition(*conditionOperation, payload)
			if err != nil {
				span.Error("not able evaluate expression - %v with error - %v. skipping the handler.", expressionStr, err)
			}
			if exprResult {
				actionId = dispatch.actionId
			}
		} else if exprType == condition.EXPR_TYPE_HEADER {
			span.Error("header expression type is invalid for mqtt trigger condition")
		} else if exprType == condition.EXPR_TYPE_ENV {
			//environment variable based condition
			envFlagValue := os.Getenv(conditionOperation.LHS)
			log.Debugf("environment flag = %v, val = %v", conditionOperation.LHS, envFlagValue)
			if envFlagValue != "" {
				conditionOperation.LHS = envFlagValue
				op := conditionOperation.Operator
				exprResult := op.Eval(conditionOperation.LHS, conditionOperation.RHS)
				if exprResult {
					actionId = dispatch.actionId
				}
			}
		}

		if actionId != "" {
			log.Debugf("dispatch resolved with the actionId - %v", actionId)
			break
		}
	}

	//If no dispatch is found, use default action
	if actionId == "" {
		actionId = h.defaultActionId
		log.Debugf("dispatch not resolved. Continue with default action - %v", actionId)
	}

	return actionId
}

//Dispatch holds dispatch actionId and condition
type Dispatch struct {
	actionId  string
	condition string
}

// eftlTrigger is a stub for your Trigger implementation
type eftlTrigger struct {
	metadata              *trigger.Metadata
	runner                action.Runner
	config                *trigger.Config
	handlers              map[string]*OptimizedHandler
	destinationToActionId map[string]string
}

//NewFactory create a new Trigger factory
func NewFactory(md *trigger.Metadata) trigger.Factory {
	return &eftlFactory{metadata: md}
}

// eftlFactory Trigger factory
type eftlFactory struct {
	metadata *trigger.Metadata
}

//New Creates a new trigger instance for a given id
func (t *eftlFactory) New(config *trigger.Config) trigger.Trigger {
	eftlTrigger := &eftlTrigger{metadata: t.metadata, config: config}
	return eftlTrigger
}

// Metadata implements trigger.Trigger.Metadata
func (t *eftlTrigger) Metadata() *trigger.Metadata {
	return t.metadata
}

// Init implements ext.Trigger.Init
func (t *eftlTrigger) Init(runner action.Runner) {
	t.runner = runner
}

// CreateHandlers creates handlers mapped to thier destination matcher
func (t *eftlTrigger) CreateHandlers() map[string]*OptimizedHandler {
	handlers := make(map[string]*OptimizedHandler)

	for _, h := range t.config.Handlers {

		t := h.Settings[settingDestination]
		if t == nil {
			continue
		}

		matcher := createMatcher(h)
		handler := handlers[matcher]
		if handler == nil {
			handler = &OptimizedHandler{}
			handlers[matcher] = handler
		}

		if condition := h.Settings[util.Flogo_Trigger_Handler_Setting_Condition]; condition != nil {
			dispatch := &Dispatch{
				actionId:  h.ActionId,
				condition: condition.(string),
			}
			handler.dispatches = append(handler.dispatches, dispatch)
		} else {
			handler.defaultActionId = h.ActionId
		}
	}

	return handlers
}

// configureTracer configures the distributed tracer
func (t *eftlTrigger) configureTracer() {
	tracer := TracerNoOP
	if setting, ok := t.config.Settings[settingTracer]; ok {
		tracer = setting.(string)
	}
	tracerEndpoint := ""
	if setting, ok := t.config.Settings[settingTracerEndpoint]; ok {
		tracerEndpoint = setting.(string)
	}
	tracerToken := ""
	if setting, ok := t.config.Settings[settingTracerToken]; ok {
		tracerToken = setting.(string)
	}
	tracerDebug := false
	if setting, ok := t.config.Settings[settingTracerDebug]; ok {
		tracerDebug = setting.(bool)
	}
	tracerSameSpan := false
	if setting, ok := t.config.Settings[settingTracerSameSpan]; ok {
		tracerSameSpan = setting.(bool)
	}
	tracerID128Bit := true
	if setting, ok := t.config.Settings[settingTracerID128Bit]; ok {
		tracerID128Bit = setting.(bool)
	}

	switch tracer {
	case TracerNoOP:
		opentracing.SetGlobalTracer(&opentracing.NoopTracer{})
	case TracerZipKin:
		if tracerEndpoint == "" {
			panic(ErrorTracerEndpointRequired)
		}

		collector, err := zipkin.NewHTTPCollector(tracerEndpoint)
		if err != nil {
			panic(fmt.Sprintf("unable to create Zipkin HTTP collector: %+v\n", err))
		}

		recorder := zipkin.NewRecorder(collector, tracerDebug,
			getLocalIP(), t.config.Name)

		tracer, err := zipkin.NewTracer(
			recorder,
			zipkin.ClientServerSameSpan(tracerSameSpan),
			zipkin.TraceID128Bit(tracerID128Bit),
		)
		if err != nil {
			panic(fmt.Sprintf("unable to create Zipkin tracer: %+v\n", err))
		}

		opentracing.SetGlobalTracer(tracer)
	case TracerAPPDash:
		if tracerEndpoint == "" {
			panic(ErrorTracerEndpointRequired)
		}

		collector := appdash.NewRemoteCollector(tracerEndpoint)
		chunkedCollector := appdash.NewChunkedCollector(collector)
		tracer := appdashtracing.NewTracer(chunkedCollector)
		opentracing.SetGlobalTracer(tracer)
	case TracerLightStep:
		if tracerToken == "" {
			panic(ErrorTracerTokenRequired)
		}

		lightstepTracer := lightstep.NewTracer(lightstep.Options{
			AccessToken: tracerToken,
		})

		opentracing.SetGlobalTracer(lightstepTracer)
	default:
		panic(ErrorInvalidTracer)
	}
}

// getLocalIP gets the public ip address of the system
func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "0.0.0.0"
	}
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return "0.0.0.0"
}

// Start implements trigger.Trigger.Start
func (t *eftlTrigger) Start() error {

	// start the trigger
	wsHost := t.config.GetSetting("server")
	wsClientID := t.config.GetSetting("clientid")
	wsChannel := t.config.GetSetting("channel")
	wsUser := t.config.GetSetting("user")
	wsPassword := t.config.GetSetting("password")
	wsSecure, err := strconv.ParseBool(t.config.GetSetting("secure"))
	if err != nil {
		return err
	}
	wsCert := ""
	if wsSecure {
		wsCert = t.config.GetSetting("certificate")
	}

	wsURL := url.URL{}
	if wsSecure {
		wsURL = url.URL{Scheme: "wss", Host: wsHost, Path: wsChannel}
	} else {
		wsURL = url.URL{Scheme: "ws", Host: wsHost, Path: wsChannel}
	}
	wsConn := wsURL.String()

	var tlsConfig *tls.Config

	if wsCert != "" {
		// TLS configuration uses CA certificate from a PEM file to
		// authenticate the server certificate when using wss:// for
		// a secure connection
		caCert, err := base64.StdEncoding.DecodeString(wsCert)
		if err != nil {
			log.Errorf("unable to decode certificate: %s", err)
			return err
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

	t.configureTracer()

	t.handlers = t.CreateHandlers()

	// Create array of channels for all handlers
	msgChans := make([]chan eftl.Message, len(t.config.Handlers))

	// Error channel for receiving connection errors
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
		log.Errorf("Error connecing to eFTL server: [%s]", err)
		return err
	}

	// close the connection when done
	defer conn.Disconnect()

	//Subscribe to destination in endpoints
	for i, handler := range t.config.Handlers {
		msgChans[i] = make(chan eftl.Message)

		matcher := createMatcher(handler)
		durablename := ""
		durable, err := strconv.ParseBool(handler.GetSetting("durable"))
		if err != nil {
			return err
		}
		if durable {
			durablename = handler.GetSetting("durablename")
		}
		log.Infof("created matcher: %v", matcher)
		_, err = conn.Subscribe(matcher, durablename, msgChans[i])
		if err != nil {
			log.Infof("Error subscribing with matcher %s", err)
		} else {
			log.Infof("Subscribe succesful: %s", matcher)
		}
	}

	for {
		cases := make([]reflect.SelectCase, len(msgChans))
		for i, ch := range msgChans {
			cases[i] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(ch)}
		}
		remaining := len(cases)
		for remaining > 0 {
			chosen, value, ok := reflect.Select(cases)
			fmt.Printf("Read from channel %#v and received %s\n", chosen, value)
			log.Infof("received message: %s", value)
			if !ok {
				// The chosen channel has been closed, so zero out the channel to disable the case
				cases[chosen].Chan = reflect.ValueOf(nil)
				remaining--
				continue
			}
			//Get eFTL message from value
			msg, ok := value.Interface().(eftl.Message)
			if !ok {
				log.Error("Error casting regular message type")
				continue
			}
			message := msg["text"].(string)
			log.Infof("Message Payload: %v", message)
			destination := msg["_dest"].(string)
			log.Infof("Message Destination: %v", destination)
			subject := msg["_subj"].(string)
			log.Infof("Message Subject: %v", subject)
			matcher := createMatcher(t.config.Handlers[chosen])
			span := Span{
				Span: opentracing.StartSpan(matcher),
			}
			defer span.Finish()

			handler, found := t.handlers[matcher]
			if found {
				t.RunAction(handler.GetActionID(message, span), message, destination, subject, span)
			} else {
				span.Error("Matcher %s not found", matcher)
			}

		}
	}

	return nil
}

// Stop implements trigger.Trigger.Start
func (t *eftlTrigger) Stop() error {
	// stop the trigger
	return nil
}

// RunAction starts a new Process Instance
func (t *eftlTrigger) RunAction(actionId string, payload string, destination string, subject string, span Span) {
	log.Debug("Starting new Process Instance")
	log.Debugf("Action Id: %s", actionId)

	req := t.constructStartRequest(payload, destination, subject, span)

	startAttrs, _ := t.metadata.OutputsToAttrs(req.Data, false)

	action := action.Get(actionId)

	context := trigger.NewContext(context.Background(), startAttrs)

	_, replyData, err := t.runner.Run(context, action, actionId, nil)
	if err != nil {
		log.Error(err)
	}

	log.Debugf("Ran action: [%s]", actionId)
	log.Debugf("Reply data: [%v]", replyData)

}

func (t *eftlTrigger) constructStartRequest(message string, destination string, subject string, span Span) *StartRequest {

	span.SetTag("message", message)
	span.SetTag("destination", destination)
	span.SetTag("subject", subject)

	ctx := opentracing.ContextWithSpan(context.Background(), span)

	//TODO how to handle reply to, reply feature
	req := &StartRequest{}
	data := make(map[string]interface{})
	data["message"] = message
	data["destination"] = destination
	data["subject"] = subject
	data["tracing"] = ctx
	req.Data = data
	return req
}

// StartRequest describes a request for starting a ProcessInstance
type StartRequest struct {
	ProcessURI  string                 `json:"flowUri"`
	Data        map[string]interface{} `json:"data"`
	Interceptor *support.Interceptor   `json:"interceptor"`
	Patch       *support.Patch         `json:"patch"`
	ReplyTo     string                 `json:"replyTo"`
}

func convert(b []byte) string {
	n := len(b)
	return string(b[:n])
}

func createMatcher(handler *trigger.HandlerConfig) string {
	// create the message content matcher
	//complex matcher format like '{"_dest":"subject"}' can be used directly
	matcher := handler.GetSetting("destination")
	if string(matcher[0:1]) != "{" {
		// simple destination, will need to form matcher
		matcher = fmt.Sprintf("{\"_dest\":\"%s\"}", handler.GetSetting("destination"))
	}
	usesubject, err := strconv.ParseBool(handler.GetSetting("usesubject"))
	if err != nil {
		return matcher
	}
	subject := ""
	if usesubject {
		subject = handler.GetSetting("subject")
		if subject != "" {
			log.Infof("got subject: %v", subject)
			matchlen := len(matcher) - 1
			matcher = matcher[0:matchlen] + ", \"_subj\":\"" + subject + "\"}"
		}
	}
	return matcher
}
