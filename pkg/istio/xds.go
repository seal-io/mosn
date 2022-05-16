/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package istio

import (
	"context"
	"errors"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/clock"
	"mosn.io/pkg/utils"

	"mosn.io/mosn/pkg/config/v2"
	"mosn.io/mosn/pkg/log"
)

type XdsStreamConfig interface {
	CreateXdsStreamClient() (XdsStreamClient, error)
	InitAdsRequest() interface{}
}

type ADSClient struct {
	streamClientMutex sync.RWMutex
	streamClient      XdsStreamClient
	config            XdsStreamConfig
	stopChan          chan struct{}
}

func NewAdsClient(config *v2.MOSNConfig) (*ADSClient, error) {
	cfg, err := ParseAdsConfig(config.RawDynamicResources, config.RawStaticResources)
	if err != nil {
		return nil, err
	}
	return &ADSClient{
		config:   cfg,
		stopChan: make(chan struct{}),
	}, nil
}

type XdsStreamClient interface {
	Send(req interface{}) error
	Recv() (interface{}, error)
	HandleResponse(resp interface{})
	Stop()
}

func (adsClient *ADSClient) GetStreamClient() (c XdsStreamClient) {
	adsClient.streamClientMutex.RLock()
	c = adsClient.streamClient
	adsClient.streamClientMutex.RUnlock()
	return
}

func (adsClient *ADSClient) Start(ctx context.Context) {
	if adsClient.config == nil {
		log.StartLogger.Infof("[xds] [ads client] no xds config parsed, no xds action")
		return
	}
	var err = adsClient.connect(ctx)
	if err != nil {
		log.StartLogger.Infof("[xds] [ads client] failed to connect: %v", err)
	}
	utils.GoWithRecover(func() { adsClient.receiveResponseLoop(ctx) }, nil)
}

func (adsClient *ADSClient) receiveResponseLoop(ctx context.Context) {
	var backoff = wait.NewExponentialBackoffManager(
		1*time.Second,
		16*time.Second,
		5*time.Minute,
		1.5,
		0.2,
		&clock.RealClock{},
	)
	wait.BackoffUntil(func() {
		_ = wait.PollImmediateUntilWithContext(ctx, 1*time.Second, adsClient.receiveResponse)
	}, backoff, true, ctx.Done())
}

func (adsClient *ADSClient) receiveResponse(ctx context.Context) (bool, error) {
	select {
	case <-adsClient.stopChan:
		log.DefaultLogger.Infof("[xds] [ads client] receive response loop shutdown")
		return true, nil
	default:
	}

	var cli = adsClient.GetStreamClient()
	if cli == nil {
		log.DefaultLogger.Infof("[xds] [ads client] try receive response: stream client closed")
		_ = adsClient.connect(ctx)
		return false, errors.New("nil client")
	}
	var resp, err = cli.Recv()
	if err != nil {
		log.DefaultLogger.Infof("[xds] [ads client] get resp error: %v", err)
		adsClient.reconnect(ctx)
		return false, err
	}
	cli.HandleResponse(resp)
	return false, nil
}

func (adsClient *ADSClient) reconnect(ctx context.Context) {
	adsClient.stopStreamClient()
	log.DefaultLogger.Infof("[xds] [ads client] close stream client, going to reconnect")

	var backoff = wait.Backoff{
		Duration: 1 * time.Second,
		Factor:   1.5,
		Jitter:   0.2,
		Steps:    10,
		Cap:      16 * time.Second,
	}
	_ = wait.ExponentialBackoffWithContext(ctx, backoff, func() (bool, error) {
		var err = adsClient.connect(ctx)
		if err != nil {
			log.DefaultLogger.Infof("[xds] [ads client] stream client reconnect failed: %v, going to retry", err)
			return false, nil
		}
		return true, nil
	})
}

func (adsClient *ADSClient) stopStreamClient() {
	adsClient.streamClientMutex.Lock()
	if adsClient.streamClient != nil {
		adsClient.streamClient.Stop()
		adsClient.streamClient = nil
	}
	adsClient.streamClientMutex.Unlock()
}

func (adsClient *ADSClient) connect(ctx context.Context) error {
	adsClient.streamClientMutex.Lock()
	defer adsClient.streamClientMutex.Unlock()

	if adsClient.streamClient != nil {
		return nil
	}
	client, err := adsClient.config.CreateXdsStreamClient()
	if err != nil {
		return err
	}
	err = client.Send(adsClient.config.InitAdsRequest())
	if err != nil {
		return err
	}
	adsClient.streamClient = client

	return nil
}

func (adsClient *ADSClient) Stop() {
	close(adsClient.stopChan)
}
