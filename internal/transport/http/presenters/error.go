package presenters

type ErrorResponse struct {
	Error string `json:"error"`
}

func Error(err error) *ErrorResponse {
	return &ErrorResponse{
		Error: err.Error(),
	}
}
