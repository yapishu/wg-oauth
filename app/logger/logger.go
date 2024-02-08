package logger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"
	"wg-oauth/nrapi"

	"github.com/newrelic/go-agent/v3/newrelic"
)

var (
	logPath        string
	logFile        *os.File
	multiWriter    io.Writer
	Logger         *slog.Logger
	dynamicHandler *DynamicLevelHandler
	ErrBus         = make(chan string, 100)
)

const (
	LevelInfo  = slog.LevelInfo
	LevelDebug = slog.LevelDebug
)

type MuMultiWriter struct {
	Writers []io.Writer
	Mu      sync.Mutex
}

type DynamicLevelHandler struct {
	currentLevel slog.Leveler
	handler      slog.Handler
}

func NewDynamicLevelHandler(initialLevel slog.Leveler, h slog.Handler) *DynamicLevelHandler {
	return &DynamicLevelHandler{currentLevel: initialLevel, handler: h}
}

func (d *DynamicLevelHandler) SetLevel(newLevel slog.Leveler) {
	d.currentLevel = newLevel
}

func (d *DynamicLevelHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= d.currentLevel.Level()
}

func (d *DynamicLevelHandler) Handle(ctx context.Context, r slog.Record) error {
	return d.handler.Handle(ctx, r)
}

func (d *DynamicLevelHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return NewDynamicLevelHandler(d.currentLevel, d.handler.WithAttrs(attrs))
}

func (d *DynamicLevelHandler) WithGroup(name string) slog.Handler {
	return NewDynamicLevelHandler(d.currentLevel, d.handler.WithGroup(name))
}

func (d *DynamicLevelHandler) Level() slog.Level {
	return d.currentLevel.Level()
}

type ErrorChannelHandler struct {
	underlyingHandler slog.Handler
}

func NewErrorChannelHandler(handler slog.Handler) *ErrorChannelHandler {
	return &ErrorChannelHandler{underlyingHandler: handler}
}

func (e *ErrorChannelHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return e.underlyingHandler.Enabled(ctx, level)
}

func (e *ErrorChannelHandler) Handle(ctx context.Context, r slog.Record) error {
	// If the level is Error, do something
	// if r.Level == slog.LevelError {
	// 	ErrBus <- r.Message
	// }
	return e.underlyingHandler.Handle(ctx, r)
}

func (e *ErrorChannelHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return NewErrorChannelHandler(e.underlyingHandler.WithAttrs(attrs))
}

func (e *ErrorChannelHandler) WithGroup(name string) slog.Handler {
	return NewErrorChannelHandler(e.underlyingHandler.WithGroup(name))
}

func init() {
	basePath := os.Getenv("DB_PATH")
	logPath = basePath + "logs/"
	err := os.MkdirAll(logPath, 0755)
	if err != nil {
		fmt.Println(fmt.Sprintf("Failed to create log directory: %v", err))
	}
	logFile, err := os.OpenFile(SysLogfile(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(fmt.Sprintf("Failed to open log file: %v", err))
	}
	multiWriter = muMultiWriter(os.Stdout, logFile)
	jsonHandler := slog.NewJSONHandler(multiWriter, nil)
	var level slog.Level
	// run like `./app dev` to print debug logs
	for _, arg := range os.Args[1:] {
		if arg == "dev" {
			level = LevelDebug
		} else {
			level = LevelInfo
		}
	}
	dynamicHandler = NewDynamicLevelHandler(level, jsonHandler)
	// customHandler := NewErrorChannelHandler(dynamicHandler)
	nrHandler := NewNewRelicHandler(nrapi.App)
	compositeHandler := NewCompositeHandler(jsonHandler, nrHandler)
	Logger = slog.New(compositeHandler)
}

func ToggleDebugLogging(enable bool) {
	if enable {
		dynamicHandler.SetLevel(LevelDebug)
	} else {
		dynamicHandler.SetLevel(LevelInfo)
	}
}

func SysLogfile() string {
	currentTime := time.Now()
	return fmt.Sprintf("%s%d-%02d.log", logPath, currentTime.Year(), currentTime.Month())
}

func PrevSysLogfile() string {
	currentTime := time.Now()
	year := currentTime.Year()
	month := currentTime.Month()
	if month == time.January {
		year = year - 1
		month = time.December
	} else {
		month = month - 1
	}
	return fmt.Sprintf("%s%d-%02d.log", logPath, year, month)
}

func muMultiWriter(writers ...io.Writer) *MuMultiWriter {
	return &MuMultiWriter{
		Writers: writers,
	}
}

func (m *MuMultiWriter) Write(p []byte) (n int, err error) {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	var firstError error
	for _, w := range m.Writers {
		n, err := w.Write(p)
		if err != nil && firstError == nil {
			firstError = err
		}
		if n != len(p) && firstError == nil {
			firstError = io.ErrShortWrite
		}
	}
	return len(p), firstError
}

type NewRelicHandler struct {
	app *newrelic.Application
}

func NewNewRelicHandler(app *newrelic.Application) *NewRelicHandler {
	return &NewRelicHandler{app: app}
}

func (nr *NewRelicHandler) Enabled(ctx context.Context, level slog.Level) bool {
	// filter by level if we want
	return true
}

func (nr *NewRelicHandler) Handle(ctx context.Context, r slog.Record) error {
	logEvent := newrelic.LogData{
		Message:   r.Message,
		Severity:  r.Level.String(),
		Timestamp: time.Now().UnixNano() / int64(time.Millisecond),
	}
	nr.app.RecordLog(logEvent)
	return nil
}

func (nr *NewRelicHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return nr
}

func (nr *NewRelicHandler) WithGroup(name string) slog.Handler {
	return nr
}

type CompositeHandler struct {
	handlers []slog.Handler
}

func NewCompositeHandler(handlers ...slog.Handler) *CompositeHandler {
	return &CompositeHandler{handlers: handlers}
}

func (c *CompositeHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, handler := range c.handlers {
		if handler.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (c *CompositeHandler) Handle(ctx context.Context, r slog.Record) error {
	for _, handler := range c.handlers {
		if handler.Enabled(ctx, r.Level) {
			if err := handler.Handle(ctx, r); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *CompositeHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	var newHandlers []slog.Handler
	for _, handler := range c.handlers {
		newHandlers = append(newHandlers, handler.WithAttrs(attrs))
	}
	return NewCompositeHandler(newHandlers...)
}

func (c *CompositeHandler) WithGroup(name string) slog.Handler {
	var newHandlers []slog.Handler
	for _, handler := range c.handlers {
		newHandlers = append(newHandlers, handler.WithGroup(name))
	}
	return NewCompositeHandler(newHandlers...)
}
