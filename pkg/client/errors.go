package client

import (
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"google.golang.org/grpc/codes"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// ErrAccountNotFound is returned when Argo CD does not know the requested account.
var ErrAccountNotFound = errors.New("argocd-connector: account not found")

// ErrInvalidAccountTarget is returned when an account name is malformed or names an account the
// connector refuses to change.
var ErrInvalidAccountTarget = errors.New("argocd-connector: invalid account target")

// accountNotFoundError reports an unknown account as codes.NotFound while keeping
// ErrAccountNotFound matchable with errors.Is.
func accountNotFoundError(format string, args ...any) error {
	err := fmt.Errorf("%w: "+format, append([]any{ErrAccountNotFound}, args...)...)
	return uhttp.WrapErrors(codes.NotFound, err.Error(), err)
}

// invalidAccountTargetError reports a rejected account target as codes.InvalidArgument while
// keeping ErrInvalidAccountTarget matchable with errors.Is.
func invalidAccountTargetError(format string, args ...any) error {
	err := fmt.Errorf("%w: "+format, append([]any{ErrInvalidAccountTarget}, args...)...)
	return uhttp.WrapErrors(codes.InvalidArgument, err.Error(), err)
}

// httpStatusError turns a non-success Argo CD API response into an error carrying the gRPC code
// for its HTTP status, so callers can tell a permission problem from a transient failure. Rate
// limit details are attached when the response carries them.
func httpStatusError(resp *http.Response, message string) error {
	body, _ := io.ReadAll(resp.Body)
	err := fmt.Errorf("%s with status %d: %s", message, resp.StatusCode, string(body))
	return uhttp.WrapErrorsWithRateLimitInfo(uhttp.GrpcCodeFromHTTPStatus(resp.StatusCode), resp, err)
}

// kubernetesError wraps a Kubernetes API error with the gRPC code for its HTTP status. Errors
// that did not come from the API server are wrapped unchanged.
func kubernetesError(err error, message string) error {
	wrapped := fmt.Errorf("%s: %w", message, err)

	var apiStatus apierrors.APIStatus
	if errors.As(err, &apiStatus) {
		return uhttp.WrapErrors(uhttp.GrpcCodeFromHTTPStatus(int(apiStatus.Status().Code)), wrapped.Error(), wrapped)
	}
	return wrapped
}
