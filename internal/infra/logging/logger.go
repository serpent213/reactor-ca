package logging

import (
	"fmt"
	"log"
	"os"
	"time"
)

// FileLogger implements the domain.Logger interface.
type FileLogger struct {
	logger *log.Logger
	file   *os.File
}

// NewFileLogger creates a logger that writes to a file.
func NewFileLogger(logFilePath string) (*FileLogger, error) {
	file, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}
	// We don't defer file.Close() here because the logger needs it open for the lifetime of the application.
	// In this CLI model, that's until the command finishes.

	logger := log.New(file, "", 0) // No default flags, we'll format timestamps ourselves
	return &FileLogger{logger: logger, file: file}, nil
}

// formatTimestamp returns the current local time formatted with timezone followed by ": "
func (l *FileLogger) formatTimestamp() string {
	return time.Now().Format("2006/01/02 15:04:05 MST") + ": "
}

// Info logs an informational message.
func (l *FileLogger) Info(msg string, args ...interface{}) {
	l.logger.Printf(l.formatTimestamp()+"INFO: "+msg, args...)
}

// Error logs an error message.
func (l *FileLogger) Error(msg string, args ...interface{}) {
	l.logger.Printf(l.formatTimestamp()+"ERROR: "+msg, args...)
}

// Log logs a standard operation message.
func (l *FileLogger) Log(msg string) {
	l.logger.Print(l.formatTimestamp() + msg)
}
