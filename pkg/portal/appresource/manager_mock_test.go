// Code generated by MockGen. DO NOT EDIT.
// Source: manager.go

// Package appresource_test is a generated GoMock package.
package appresource_test

import (
	context "context"
	reflect "reflect"

	model "github.com/authgear/authgear-server/pkg/api/model"
	resource "github.com/authgear/authgear-server/pkg/util/resource"
	gomock "github.com/golang/mock/gomock"
)

// MockDenoClient is a mock of DenoClient interface.
type MockDenoClient struct {
	ctrl     *gomock.Controller
	recorder *MockDenoClientMockRecorder
}

// MockDenoClientMockRecorder is the mock recorder for MockDenoClient.
type MockDenoClientMockRecorder struct {
	mock *MockDenoClient
}

// NewMockDenoClient creates a new mock instance.
func NewMockDenoClient(ctrl *gomock.Controller) *MockDenoClient {
	mock := &MockDenoClient{ctrl: ctrl}
	mock.recorder = &MockDenoClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDenoClient) EXPECT() *MockDenoClientMockRecorder {
	return m.recorder
}

// Check mocks base method.
func (m *MockDenoClient) Check(ctx context.Context, snippet string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Check", ctx, snippet)
	ret0, _ := ret[0].(error)
	return ret0
}

// Check indicates an expected call of Check.
func (mr *MockDenoClientMockRecorder) Check(ctx, snippet interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Check", reflect.TypeOf((*MockDenoClient)(nil).Check), ctx, snippet)
}

// MockTutorialService is a mock of TutorialService interface.
type MockTutorialService struct {
	ctrl     *gomock.Controller
	recorder *MockTutorialServiceMockRecorder
}

// MockTutorialServiceMockRecorder is the mock recorder for MockTutorialService.
type MockTutorialServiceMockRecorder struct {
	mock *MockTutorialService
}

// NewMockTutorialService creates a new mock instance.
func NewMockTutorialService(ctrl *gomock.Controller) *MockTutorialService {
	mock := &MockTutorialService{ctrl: ctrl}
	mock.recorder = &MockTutorialServiceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockTutorialService) EXPECT() *MockTutorialServiceMockRecorder {
	return m.recorder
}

// OnUpdateResource0 mocks base method.
func (m *MockTutorialService) OnUpdateResource0(ctx context.Context, appID string, resourcesInAllFss []resource.ResourceFile, resourceInTargetFs *resource.ResourceFile, data []byte) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "OnUpdateResource0", ctx, appID, resourcesInAllFss, resourceInTargetFs, data)
	ret0, _ := ret[0].(error)
	return ret0
}

// OnUpdateResource0 indicates an expected call of OnUpdateResource0.
func (mr *MockTutorialServiceMockRecorder) OnUpdateResource0(ctx, appID, resourcesInAllFss, resourceInTargetFs, data interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "OnUpdateResource0", reflect.TypeOf((*MockTutorialService)(nil).OnUpdateResource0), ctx, appID, resourcesInAllFss, resourceInTargetFs, data)
}

// MockDomainService is a mock of DomainService interface.
type MockDomainService struct {
	ctrl     *gomock.Controller
	recorder *MockDomainServiceMockRecorder
}

// MockDomainServiceMockRecorder is the mock recorder for MockDomainService.
type MockDomainServiceMockRecorder struct {
	mock *MockDomainService
}

// NewMockDomainService creates a new mock instance.
func NewMockDomainService(ctrl *gomock.Controller) *MockDomainService {
	mock := &MockDomainService{ctrl: ctrl}
	mock.recorder = &MockDomainServiceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDomainService) EXPECT() *MockDomainServiceMockRecorder {
	return m.recorder
}

// ListDomains mocks base method.
func (m *MockDomainService) ListDomains(ctx context.Context, appID string) ([]*model.Domain, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListDomains", ctx, appID)
	ret0, _ := ret[0].([]*model.Domain)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListDomains indicates an expected call of ListDomains.
func (mr *MockDomainServiceMockRecorder) ListDomains(ctx, appID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListDomains", reflect.TypeOf((*MockDomainService)(nil).ListDomains), ctx, appID)
}
