package ui

func Select(verbose, quiet bool) UI {
	return LoggerUI
}
