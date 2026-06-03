package main

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorGreen  = "\033[32m"
)

func red(s string) string    { return colorRed + s + colorReset }
func yellow(s string) string { return colorYellow + s + colorReset }
func green(s string) string  { return colorGreen + s + colorReset }
