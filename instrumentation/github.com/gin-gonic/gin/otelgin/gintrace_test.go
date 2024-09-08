// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Based on https://github.com/DataDog/dd-trace-go/blob/8fb554ff7cf694267f9077ae35e27ce4689ed8b6/contrib/gin-gonic/gin/gintrace_test.go

package otelgin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	b3prop "go.opentelemetry.io/contrib/propagators/b3"
)

func init() {
	gin.SetMode(gin.ReleaseMode) // silence annoying log msgs
}

func TestGetSpanNotInstrumented(t *testing.T) {
	router := gin.New()
	router.GET("/ping", func(c *gin.Context) {
		// Assert we don't have a span on the context.
		span := trace.SpanFromContext(c.Request.Context())
		ok := !span.SpanContext().IsValid()
		if !ok {
			c.Status(http.StatusInternalServerError)
		}
	})
	r := httptest.NewRequest("GET", "/ping", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	response := w.Result() //nolint:bodyclose // False positive for httptest.ResponseRecorder: https://github.com/timakin/bodyclose/issues/59.
	assert.Equal(t, http.StatusOK, response.StatusCode)
}

func TestPropagationWithGlobalPropagators(t *testing.T) {
	provider := noop.NewTracerProvider()
	otel.SetTextMapPropagator(b3prop.New())

	r := httptest.NewRequest("GET", "/user/123", nil)
	w := httptest.NewRecorder()

	ctx := context.Background()
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{0x01},
		SpanID:  trace.SpanID{0x01},
	})
	ctx = trace.ContextWithRemoteSpanContext(ctx, sc)
	ctx, _ = provider.Tracer(ScopeName).Start(ctx, "test")
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(r.Header))

	router := gin.New()
	router.Use(Middleware("foobar", WithTracerProvider(provider)))
	resCh := make(chan trace.Span, 1)
	router.GET("/user/:id", func(c *gin.Context) {
		resCh <- trace.SpanFromContext(c.Request.Context())
	})

	router.ServeHTTP(w, r)

	select {
	case span := <-resCh:
		assert.Equal(t, sc.TraceID(), span.SpanContext().TraceID())
		assert.Equal(t, sc.SpanID(), span.SpanContext().SpanID())
	case <-time.After(5 * time.Second):
		t.Fatal("did not receive signal in 5s")
	}
}

func TestPropagationWithCustomPropagators(t *testing.T) {
	provider := noop.NewTracerProvider()
	b3 := b3prop.New()

	r := httptest.NewRequest("GET", "/user/123", nil)
	w := httptest.NewRecorder()

	ctx := context.Background()
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{0x01},
		SpanID:  trace.SpanID{0x01},
	})
	ctx = trace.ContextWithRemoteSpanContext(ctx, sc)
	ctx, _ = provider.Tracer(ScopeName).Start(ctx, "test")
	b3.Inject(ctx, propagation.HeaderCarrier(r.Header))

	router := gin.New()
	router.Use(Middleware("foobar", WithTracerProvider(provider), WithPropagators(b3)))
	resCh := make(chan trace.Span, 1)
	router.GET("/user/:id", func(c *gin.Context) {
		resCh <- trace.SpanFromContext(c.Request.Context())
	})

	router.ServeHTTP(w, r)

	select {
	case span := <-resCh:
		assert.Equal(t, sc.TraceID(), span.SpanContext().TraceID())
		assert.Equal(t, sc.SpanID(), span.SpanContext().SpanID())
	case <-time.After(5 * time.Second):
		t.Fatal("did not receive signal in 5s")
	}
}

func TestClientIP(t *testing.T) {
	testFn := func(requestFn func(r *http.Request), ginFn func(router *gin.Engine), expect string) func(t *testing.T) {
		return func(t *testing.T) {
			r := httptest.NewRequest("GET", "/ping", nil)
			r.RemoteAddr = "1.2.3.4:5678"

			if requestFn != nil {
				requestFn(r)
			}

			sr := tracetest.NewSpanRecorder()
			provider := sdktrace.NewTracerProvider()
			provider.RegisterSpanProcessor(sr)

			doneCh := make(chan struct{})
			router := gin.New()

			if ginFn != nil {
				ginFn(router)
			}

			router.Use(Middleware("foobar", WithTracerProvider(provider)))
			router.GET("/ping", func(c *gin.Context) {
				close(doneCh)
			})

			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)
			response := w.Result() //nolint:bodyclose // False positive for httptest.ResponseRecorder: https://github.com/timakin/bodyclose/issues/59.
			assert.Equal(t, http.StatusOK, response.StatusCode)

			select {
			case <-doneCh:
				// nop
			case <-time.After(5 * time.Second):
				t.Fatal("did not receive signal in 5s")
			}

			res := sr.Ended()
			require.Len(t, res, 1)

			got := make(map[attribute.Key]attribute.Value, len(res[0].Attributes()))
			for _, a := range res[0].Attributes() {
				got[a.Key] = a.Value
			}

			require.NotEmpty(t, got["http.client_ip"])
			assert.Equal(t, expect, got["http.client_ip"].AsString())
		}
	}

	t.Run("no header", testFn(nil, nil, "1.2.3.4"))

	t.Run("header is not trusted", testFn(
		func(r *http.Request) {
			r.Header.Set("X-Forwarded-For", "9.8.7.6")
		},
		func(router *gin.Engine) {
			router.SetTrustedProxies(nil)
		},
		"1.2.3.4",
	))

	t.Run("client IP in X-Forwarded-For header", testFn(
		func(r *http.Request) {
			r.Header.Set("X-Forwarded-For", "9.8.7.6")
		},
		func(router *gin.Engine) {
			router.SetTrustedProxies([]string{"0.0.0.0/0"})
		},
		"9.8.7.6",
	))

	t.Run("client IP in X-Custom-IP", testFn(
		func(r *http.Request) {
			r.Header.Set("X-Forwarded-For", "2.3.2.3") // not used
			r.Header.Set("X-Custom-IP", "9.8.7.6")
		},
		func(router *gin.Engine) {
			router.RemoteIPHeaders = []string{"X-Custom-IP", "X-Forwarded-For"}
			router.SetTrustedProxies([]string{"0.0.0.0/0"})
		},
		"9.8.7.6",
	))
}
