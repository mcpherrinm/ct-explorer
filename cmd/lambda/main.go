package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"

	"transparency/internal/api"
	"transparency/internal/ct"
)

var analyzer = ct.NewAnalyzer(nil)

func handle(ctx context.Context, req events.LambdaFunctionURLRequest) (events.LambdaFunctionURLResponse, error) {
	if req.RequestContext.HTTP.Method == "OPTIONS" {
		return response(204, nil)
	}
	if req.RequestContext.HTTP.Method != "GET" {
		return response(405, api.ErrorBody(errors.New("use GET")))
	}

	target := strings.TrimSpace(req.QueryStringParameters["url"])
	if target == "" {
		return response(400, api.ErrorBody(errors.New("missing url query parameter")))
	}

	report, err := analyzer.Analyze(ctx, target)
	if err != nil {
		return response(400, api.ErrorBody(err))
	}
	return response(200, report)
}

func response(status int, payload any) (events.LambdaFunctionURLResponse, error) {
	headers := api.CORSHeaders()
	if payload == nil {
		return events.LambdaFunctionURLResponse{
			StatusCode: status,
			Headers:    headers,
		}, nil
	}

	body, err := json.Marshal(payload)
	if err != nil {
		status = 500
		body, _ = json.Marshal(api.ErrorBody(errors.New("encode response")))
	}
	return events.LambdaFunctionURLResponse{
		StatusCode: status,
		Headers:    headers,
		Body:       string(body),
	}, nil
}

func main() {
	lambda.Start(handle)
}
