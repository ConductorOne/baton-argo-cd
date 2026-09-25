package client

import (
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/conductorone/baton-sdk/pkg/ratelimit"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// ErrAccountNotFound is returned when Argo CD does not know the requested account.
var ErrAccountNotFound = errors.New("argocd-connector: account not found")

// ErrInvalidAccountTarget is returned when an account name is malformed or names an account the
// connector refuses to change.
var ErrInvalidAccountTarget = errors.New("argocd-connector: invalid account target")

// codedError carries a gRPC status for its cause without repeating the cause's message:
// status.Code reads the code through GRPCStatus, and errors.Is / errors.As reach the cause
// through Unwrap.
type codedError struct {
	status *status.Status
	cause  error
}

func (e *codedError) Error() string              { return e.cause.Error() }
func (e *codedError) Unwrap() error              { return e.cause }
func (e *codedError) GRPCStatus() *status.Status { return e.status }

func withCode(code codes.Code, cause error) error {
	return &codedError{status: status.New(code, cause.Error()), cause: cause}
}

// accountNotFoundError reports an unknown account as codes.NotFound while keeping
// ErrAccountNotFound matchable with errors.Is.
func accountNotFoundError(format string, args ...any) error {
	return withCode(codes.NotFound, fmt.Errorf("%w: "+format, append([]any{ErrAccountNotFound}, args...)...))
}

// invalidAccountTargetError reports a rejected account target as codes.InvalidArgument while
// keeping ErrInvalidAccountTarget matchable with errors.Is.
func invalidAccountTargetError(format string, args ...any) error {
	return withCode(codes.InvalidArgument, fmt.Errorf("%w: "+format, append([]any{ErrInvalidAccountTarget}, args...)...))
}

// httpStatusError turns a non-success Argo CD API response into an error carrying the gRPC code
// for its HTTP status, so callers can tell a permission problem from a transient failure. Rate
// limit details are attached when the response carries them.
func httpStatusError(resp *http.Response, message string) error {
	body, _ := io.ReadAll(resp.Body)
	cause := fmt.Errorf("%s with status %d: %s", message, resp.StatusCode, string(body))

	st := status.New(uhttp.GrpcCodeFromHTTPStatus(resp.StatusCode), cause.Error())
	if description, err := ratelimit.ExtractRateLimitData(resp.StatusCode, &resp.Header); err == nil && description != nil {
		if withDetails, err := st.WithDetails(description); err == nil {
			st = withDetails
		}
	}
	return &codedError{status: st, cause: cause}
}

// kubernetesError wraps a Kubernetes API error with the gRPC code for its HTTP status. Errors
// that did not come from the API server are wrapped unchanged.
func kubernetesError(err error, message string) error {
	wrapped := fmt.Errorf("%s: %w", message, err)

	var apiStatus apierrors.APIStatus
	if errors.As(err, &apiStatus) {
		return withCode(uhttp.GrpcCodeFromHTTPStatus(int(apiStatus.Status().Code)), wrapped)
	}
	return wrapped
}
