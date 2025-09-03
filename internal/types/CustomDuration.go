package types

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// CustomDuration supports parsing durations with units like "s", "m", "h", "d", "mo".
type CustomDuration time.Duration

func (d *CustomDuration) UnmarshalText(text []byte) error {
	str := string(text)
	if len(str) < 2 {
		return fmt.Errorf("invalid duration format: %s", str)
	}

	var multiplier time.Duration
	var value string

	if strings.HasSuffix(str, "mo") { // months
		multiplier = time.Hour * 24 * 30
		value = str[:len(str)-2]
	} else {
		unit := str[len(str)-1]
		value = str[:len(str)-1]

		switch unit {
		case 's': // seconds
			multiplier = time.Second
		case 'm': // minutes
			multiplier = time.Minute
		case 'h': // hours
			multiplier = time.Hour
		case 'd': // days
			multiplier = time.Hour * 24
		default:
			return fmt.Errorf("unknown duration unit: %c", unit)
		}
	}

	parsedValue, err := strconv.Atoi(value)
	if err != nil {
		return fmt.Errorf("invalid duration value: %s", value)
	}

	*d = CustomDuration(time.Duration(parsedValue) * multiplier)
	return nil
}

func (d CustomDuration) Duration() time.Duration {
	return time.Duration(d)
}
