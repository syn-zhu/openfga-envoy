package authz

import (
	"context"
	"errors"
	"fmt"

	envoy "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	openfga "github.com/openfga/go-sdk"
	"github.com/openfga/go-sdk/client"
	"github.com/openfga/openfga-envoy/extauthz/internal/extractor"
	"github.com/openfga/openfga/pkg/logger"
	"go.uber.org/zap"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

var (
	// Response for a successful authorization.
	allow = &envoy.CheckResponse{
		Status: &status.Status{
			Code:    int32(codes.OK),
			Message: "",
		},
	}

	deny = func(code codes.Code, message string) *envoy.CheckResponse {
		return &envoy.CheckResponse{
			Status: &status.Status{
				Code:    int32(code),
				Message: message,
			},
		}
	}
)

// ExtAuthZFilter is an implementation of the Envoy AuthZ filter.
type ExtAuthZFilter struct {
	enforce        bool
	client         *client.OpenFgaClient
	extractionKits []extractor.ExtractorKit
	modelID        string
	logger         logger.Logger

	// Per-request store resolution.
	// When storeIDHeader is set, the filter reads the OpenFGA store_id from that
	// request header instead of using the client's default store_id.
	storeIDHeader string
}

var _ envoy.AuthorizationServer = (*ExtAuthZFilter)(nil)

type Config struct {
	Enforce        bool
	ExtractionKits []extractor.ExtractorKit
	// StoreIDHeader is the request header name containing the OpenFGA store_id.
	// If set, overrides the config-level store_id on a per-request basis.
	StoreIDHeader string
}

// NewExtAuthZFilter creates a new ExtAuthZFilter
func NewExtAuthZFilter(config Config, c *client.OpenFgaClient, logger logger.Logger) *ExtAuthZFilter {
	return &ExtAuthZFilter{
		enforce:        config.Enforce,
		client:         c,
		extractionKits: config.ExtractionKits,
		logger:         logger,
		storeIDHeader:  config.StoreIDHeader,
	}
}

func (e *ExtAuthZFilter) Register(server *grpc.Server) {
	envoy.RegisterAuthorizationServer(server, e)
}

// Check the access decision based on the incoming request
func (e *ExtAuthZFilter) Check(ctx context.Context, req *envoy.CheckRequest) (response *envoy.CheckResponse, err error) {
	reqID := req.Attributes.GetRequest().GetHttp().GetHeaders()["x-request-id"]
	logger := e.logger
	if reqID != "" {
		logger = e.logger.With(zap.String("request_id", reqID))
	}

	res, err := e.check(ctx, req, logger)
	if e.enforce {
		if err != nil {
			logger.Error("Failed to check permissions", zap.Error(err))
			return nil, err
		}

		return res, nil
	} else {
		if err != nil {
			logger.Error("Failed to check permissions", zap.Error(err))
		}

		return allow, nil
	}
}

func (e *ExtAuthZFilter) extract(ctx context.Context, req *envoy.CheckRequest) (*extractor.Check, error) {
	for _, es := range e.extractionKits {
		e.logger.Debug("Extracting values", zap.String("extractor", es.Name))
		check, err := es.Extract(ctx, req)
		if err == nil {
			return check, nil
		}

		if errors.Is(err, extractor.ErrValueNotFound) {
			e.logger.Debug("Extracing value not found", zap.String("extraction_kit", es.Name), zap.Error(err))
			continue
		}

		return nil, err
	}

	return nil, nil
}

// resolveStoreID returns the store_id to use for this request.
// Returns nil if the default (config-level) store_id should be used.
func (e *ExtAuthZFilter) resolveStoreID(headers map[string]string, logger logger.Logger) (*string, error) {
	if e.storeIDHeader != "" {
		if storeID, ok := headers[e.storeIDHeader]; ok && storeID != "" {
			logger.Debug("Using store_id from header", zap.String("header", e.storeIDHeader), zap.String("store_id", storeID))
			return &storeID, nil
		}
	}

	// Fall back to the default (config-level) store_id.
	return nil, nil
}

// check implements the Check method of the Authorization interface.
func (e *ExtAuthZFilter) check(ctx context.Context, req *envoy.CheckRequest, logger logger.Logger) (response *envoy.CheckResponse, err error) {
	check, err := e.extract(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("extracting values from request: %w", err)
	}

	if check == nil {
		logger.Error("Failed to extract values from request")
		return deny(codes.InvalidArgument, "No extraction set found"), nil
	}

	// Resolve the store_id for this request (may differ from config-level default).
	headers := req.Attributes.GetRequest().GetHttp().GetHeaders()
	storeID, err := e.resolveStoreID(headers, logger)
	if err != nil {
		logger.Error("Failed to resolve store_id", zap.Error(err))
		return deny(codes.Internal, fmt.Sprintf("Error resolving store: %v", err)), nil
	}

	body := client.ClientCheckRequest{
		User:     check.User,
		Relation: check.Relation,
		Object:   check.Object,
		Context:  &check.Context,
	}

	options := client.ClientCheckOptions{
		AuthorizationModelId: openfga.PtrString(e.modelID),
		StoreId:              storeID, // nil = use config-level default
	}

	logger.Debug("Checking permissions", zap.String("user", check.User), zap.String("relation", check.Relation), zap.String("object", check.Object))
	data, err := e.client.Check(ctx).Body(body).Options(options).Execute()
	if err != nil {
		logger.Error("Failed to check permissions", zap.Error(err))
		return deny(codes.Internal, fmt.Sprintf("Error checking permissions: %v", err)), nil
	}

	if data.GetAllowed() {
		logger.Debug("Access granted", zap.String("resolution", data.GetResolution()))
		return allow, nil
	}

	logger.Debug("Access denied")
	return deny(codes.PermissionDenied, fmt.Sprintf("Access denied: %s", data.GetResolution())), nil
}
